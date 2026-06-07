import Foundation
import Flutter
import CryptoKit
import DeviceCheck

// MARK: - TeeChannel
//
// Implements the Flutter MethodChannel "com.arkos.mobile/tee" on iOS.
//
// Key operations:
//   generateDeviceKey    – creates a P-256 key in the Secure Enclave (non-extractable)
//   getDevicePublicKey   – returns DER-encoded SubjectPublicKeyInfo for the Secure Enclave key
//   signCommitment       – signs 32 bytes with the Secure Enclave P-256 key (ECDSA-SHA256)
//   getAttestationToken  – returns Apple App Attest assertion (base64) for the commitment bytes
//
// All operations are synchronous from the perspective of the MethodChannel callback;
// async work is dispatched internally and the result is returned on the main thread.

@available(iOS 13.0, *)
final class TeeChannel {

    // Keychain / SecureEnclave tag shared across calls.
    private static let keyTag = "com.arkos.mobile.device.key"

    static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(
            name: "com.arkos.mobile/tee",
            binaryMessenger: registrar.messenger()
        )
        channel.setMethodCallHandler { call, result in
            switch call.method {
            case "generateDeviceKey":
                generateDeviceKey(result: result)
            case "getDevicePublicKey":
                getDevicePublicKey(result: result)
            case "signCommitment":
                guard let args = call.arguments as? [String: Any],
                      let hexBytes = args["commitmentHex"] as? String else {
                    result(FlutterError(code: "INVALID_ARGS",
                                       message: "commitmentHex required",
                                       details: nil))
                    return
                }
                signCommitment(commitmentHex: hexBytes, result: result)
            case "getAttestationToken":
                guard let args = call.arguments as? [String: Any],
                      let hexBytes = args["challengeHex"] as? String else {
                    result(FlutterError(code: "INVALID_ARGS",
                                       message: "challengeHex required",
                                       details: nil))
                    return
                }
                getAttestationToken(commitmentHex: hexBytes, result: result)
            default:
                result(FlutterMethodNotImplemented)
            }
        }
    }

    // ── Key generation ───────────────────────────────────────────────────────

    private static func generateDeviceKey(result: @escaping FlutterResult) {
        // Delete any existing key first (idempotent re-registration).
        deleteExistingKey()

        var error: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage],
            &error
        ) else {
            result(FlutterError(code: "KEY_GEN_FAILED",
                                message: "SecAccessControl: \(error.debugDescription)",
                                details: nil))
            return
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String:            kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String:      256,
            kSecAttrTokenID as String:            kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String:    true,
                kSecAttrApplicationTag as String: keyTag.data(using: .utf8)!,
                kSecAttrAccessControl as String:  accessControl,
            ],
        ]

        var privateKey: SecKey?
        let status = SecKeyCreateRandomKey(attributes as CFDictionary, &error) as SecKey?
        if let key = status {
            privateKey = key
        } else if let err = error {
            result(FlutterError(code: "KEY_GEN_FAILED",
                                message: "SecKeyCreateRandomKey: \(err.takeRetainedValue())",
                                details: nil))
            return
        }
        _ = privateKey // stored in keychain

        // Return the hex of the uncompressed public key so Dart can forward it to the node.
        guard let pubHex = publicKeyHex() else {
            result(FlutterError(code: "KEY_READ_FAILED",
                                message: "Could not read public key after generation",
                                details: nil))
            return
        }
        result(["pubkeyHex": pubHex])
    }

    // ── Public key ───────────────────────────────────────────────────────────

    private static func getDevicePublicKey(result: @escaping FlutterResult) {
        if let hex = publicKeyHex() {
            result(["pubkeyHex": hex])
        } else {
            result(FlutterError(code: "KEY_NOT_FOUND",
                                message: "Device key not generated yet. Call generateDeviceKey first.",
                                details: nil))
        }
    }

    // ── Signing ──────────────────────────────────────────────────────────────

    private static func signCommitment(commitmentHex: String, result: @escaping FlutterResult) {
        guard let privateKey = loadPrivateKey() else {
            result(FlutterError(code: "KEY_NOT_FOUND",
                                message: "Device key not found",
                                details: nil))
            return
        }
        guard let data = Data(hexString: commitmentHex) else {
            result(FlutterError(code: "INVALID_HEX",
                                message: "commitmentHex is not valid hex",
                                details: nil))
            return
        }

        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureMessageX962SHA256,
            data as CFData,
            &error
        ) as Data? else {
            result(FlutterError(code: "SIGN_FAILED",
                                message: "SecKeyCreateSignature: \(error.debugDescription)",
                                details: nil))
            return
        }

        result(["signatureHex": signature.hexString])
    }

    // ── App Attest ───────────────────────────────────────────────────────────

    private static func getAttestationToken(commitmentHex: String, result: @escaping FlutterResult) {
        guard #available(iOS 14.0, *) else {
            // Older iOS: return a fallback marker so the node can treat it as
            // "no attestation available but device key is still present".
            result(["tokenB64": "ATTEST_UNAVAILABLE"])
            return
        }

        guard let clientDataHash = Data(hexString: commitmentHex) else {
            result(FlutterError(code: "INVALID_HEX",
                                message: "challengeHex is not valid hex",
                                details: nil))
            return
        }

        let service = DCAppAttestService.shared
        guard service.isSupported else {
            result(["tokenB64": "ATTEST_UNSUPPORTED"])
            return
        }

        // Generate a new key for App Attest (separate from the mining Secure Enclave key).
        // In production the keyId should be persisted; for simplicity we regenerate each call.
        service.generateKey { keyId, error in
            if let error = error {
                result(FlutterError(code: "ATTEST_KEY_GEN",
                                    message: error.localizedDescription,
                                    details: nil))
                return
            }
            guard let keyId = keyId else {
                result(FlutterError(code: "ATTEST_KEY_GEN",
                                    message: "nil keyId",
                                    details: nil))
                return
            }

            service.attestKey(keyId, clientDataHash: clientDataHash) { attestation, error in
                DispatchQueue.main.async {
                    if let error = error {
                        result(FlutterError(code: "ATTEST_FAILED",
                                            message: error.localizedDescription,
                                            details: nil))
                        return
                    }
                    result(["tokenB64": attestation?.base64EncodedString() ?? ""])
                }
            }
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static func loadPrivateKey() -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String:                kSecClassKey,
            kSecAttrApplicationTag as String:   keyTag.data(using: .utf8)!,
            kSecAttrKeyType as String:           kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String:             true,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else { return nil }
        return (item as! SecKey)
    }

    private static func publicKeyHex() -> String? {
        guard let privateKey = loadPrivateKey(),
              let publicKey = SecKeyCopyPublicKey(privateKey) else { return nil }

        var error: Unmanaged<CFError>?
        guard let keyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            return nil
        }
        // keyData is the uncompressed 65-byte X9.62 point (04 || X || Y).
        return keyData.hexString
    }

    private static func deleteExistingKey() {
        let query: [String: Any] = [
            kSecClass as String:              kSecClassKey,
            kSecAttrApplicationTag as String: keyTag.data(using: .utf8)!,
        ]
        SecItemDelete(query as CFDictionary)
    }
}

// MARK: - Data helpers

private extension Data {
    /// Initialises from a lowercase/uppercase hex string (must be even length).
    init?(hexString: String) {
        let stripped = hexString.hasPrefix("0x") ? String(hexString.dropFirst(2)) : hexString
        guard stripped.count % 2 == 0 else { return nil }
        var data = Data(capacity: stripped.count / 2)
        var index = stripped.startIndex
        while index < stripped.endIndex {
            let next = stripped.index(index, offsetBy: 2)
            guard let byte = UInt8(stripped[index..<next], radix: 16) else { return nil }
            data.append(byte)
            index = next
        }
        self = data
    }

    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
