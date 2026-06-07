package com.arkos.mobile

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.annotation.RequiresApi
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * TeeChannel — Android implementation of the "com.arkos.mobile/tee" Flutter MethodChannel.
 *
 * Operations:
 *   generateDeviceKey    – generates a P-256 key in Android Keystore (hardware-backed if available)
 *   getDevicePublicKey   – returns uncompressed 65-byte EC public key as hex
 *   signCommitment       – ECDSA-SHA256 over the commitment hex bytes, returns DER hex
 *   getAttestationToken  – Play Integrity token bound to the commitment hash (base64)
 */
class TeeChannel(private val context: Context) : MethodChannel.MethodCallHandler {

    companion object {
        private const val CHANNEL_NAME   = "com.arkos.mobile/tee"
        private const val KEY_ALIAS      = "com_arkos_mobile_device_key"
        private const val KEYSTORE_TYPE  = "AndroidKeyStore"

        fun register(messenger: BinaryMessenger, context: Context) {
            val channel = MethodChannel(messenger, CHANNEL_NAME)
            channel.setMethodCallHandler(TeeChannel(context))
        }
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "generateDeviceKey"   -> generateDeviceKey(result)
            "getDevicePublicKey"  -> getDevicePublicKey(result)
            "signCommitment"      -> {
                val hex = call.argument<String>("commitmentHex")
                    ?: return result.error("INVALID_ARGS", "commitmentHex required", null)
                signCommitment(hex, result)
            }
            "getAttestationToken" -> {
                val hex = call.argument<String>("challengeHex")
                    ?: return result.error("INVALID_ARGS", "challengeHex required", null)
                getAttestationToken(hex, result)
            }
            else -> result.notImplemented()
        }
    }

    // ── Key generation ────────────────────────────────────────────────────────

    private fun generateDeviceKey(result: MethodChannel.Result) {
        try {
            // Delete any existing key (idempotent re-registration).
            deleteKeyIfExists()

            val kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                KEYSTORE_TYPE
            )

            val specBuilder = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(false)   // mining runs in background

            // Request StrongBox (dedicated security chip) on API 28+; falls back to TEE.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                specBuilder.setIsStrongBoxBacked(true)
            }

            kpg.initialize(specBuilder.build())
            val keyPair = kpg.generateKeyPair()

            // Return the uncompressed public key as hex.
            val pubHex = ecPublicKeyToUncompressedHex(keyPair.public as ECPublicKey)
            result.success(mapOf("pubkeyHex" to pubHex))
        } catch (e: Exception) {
            // StrongBox may not be present on all devices; retry without it.
            try {
                deleteKeyIfExists()
                val kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC,
                    KEYSTORE_TYPE
                )
                val spec = KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
                )
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setUserAuthenticationRequired(false)
                    .build()
                kpg.initialize(spec)
                val kp = kpg.generateKeyPair()
                result.success(mapOf("pubkeyHex" to ecPublicKeyToUncompressedHex(kp.public as ECPublicKey)))
            } catch (ex: Exception) {
                result.error("KEY_GEN_FAILED", ex.message, null)
            }
        }
    }

    // ── Public key ────────────────────────────────────────────────────────────

    private fun getDevicePublicKey(result: MethodChannel.Result) {
        try {
            val ks = KeyStore.getInstance(KEYSTORE_TYPE).apply { load(null) }
            if (!ks.containsAlias(KEY_ALIAS)) {
                result.error("KEY_NOT_FOUND",
                    "Device key not generated. Call generateDeviceKey first.", null)
                return
            }
            val pubKey = ks.getCertificate(KEY_ALIAS).publicKey as ECPublicKey
            result.success(mapOf("pubkeyHex" to ecPublicKeyToUncompressedHex(pubKey)))
        } catch (e: Exception) {
            result.error("KEY_READ_FAILED", e.message, null)
        }
    }

    // ── Signing ───────────────────────────────────────────────────────────────

    private fun signCommitment(commitmentHex: String, result: MethodChannel.Result) {
        try {
            val data = commitmentHex.hexToBytes()
                ?: return result.error("INVALID_HEX", "commitmentHex is not valid hex", null)

            val ks = KeyStore.getInstance(KEYSTORE_TYPE).apply { load(null) }
            if (!ks.containsAlias(KEY_ALIAS)) {
                result.error("KEY_NOT_FOUND", "Device key not found", null)
                return
            }
            val privateKey = ks.getKey(KEY_ALIAS, null)

            val sig = Signature.getInstance("SHA256withECDSA")
            sig.initSign(privateKey)
            sig.update(data)
            val derSignature = sig.sign()

            result.success(mapOf("signatureHex" to derSignature.toHex()))
        } catch (e: Exception) {
            result.error("SIGN_FAILED", e.message, null)
        }
    }

    // ── Play Integrity ────────────────────────────────────────────────────────
    //
    // Requires google-services.json and the Play Integrity dependency in build.gradle.
    // The nonce is the SHA-256 of the mining commitment, base64url-encoded (no padding).
    // On failure (emulator, sideloaded APK, etc.) returns "INTEGRITY_UNAVAILABLE".

    private fun getAttestationToken(commitmentHex: String, result: MethodChannel.Result) {
        try {
            val data = commitmentHex.hexToBytes()
                ?: return result.error("INVALID_HEX", "challengeHex is not valid hex", null)

            // Play Integrity nonce must be base64url, 16–500 bytes, no padding.
            val nonce = Base64.encodeToString(data, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

            val integrityManager = IntegrityManagerFactory.create(context)
            val tokenRequest = IntegrityTokenRequest.builder()
                .setNonce(nonce)
                .build()

            integrityManager.requestIntegrityToken(tokenRequest)
                .addOnSuccessListener { response ->
                    result.success(mapOf("tokenB64" to response.token()))
                }
                .addOnFailureListener { exception ->
                    // Non-fatal: node should still accept blocks with device key sig.
                    result.success(mapOf("tokenB64" to "INTEGRITY_UNAVAILABLE:${exception.message}"))
                }
        } catch (e: Exception) {
            // Play Integrity API not available on this device/environment.
            result.success(mapOf("tokenB64" to "INTEGRITY_UNAVAILABLE:${e.message}"))
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private fun deleteKeyIfExists() {
        val ks = KeyStore.getInstance(KEYSTORE_TYPE).apply { load(null) }
        if (ks.containsAlias(KEY_ALIAS)) ks.deleteEntry(KEY_ALIAS)
    }

    /**
     * Returns the uncompressed 65-byte representation: 04 || X (32 bytes) || Y (32 bytes).
     * Java's ECPublicKey.encoded is SubjectPublicKeyInfo DER; we extract W from it.
     */
    private fun ecPublicKeyToUncompressedHex(pubKey: ECPublicKey): String {
        val w = pubKey.w
        val x = w.affineX.toByteArray().stripLeadingZeroPad(32)
        val y = w.affineY.toByteArray().stripLeadingZeroPad(32)
        val uncompressed = ByteArray(65)
        uncompressed[0] = 0x04
        x.copyInto(uncompressed, 1)
        y.copyInto(uncompressed, 33)
        return uncompressed.toHex()
    }
}

// ── Extension helpers ─────────────────────────────────────────────────────────

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

private fun String.hexToBytes(): ByteArray? {
    val s = if (startsWith("0x")) substring(2) else this
    if (s.length % 2 != 0) return null
    return try {
        ByteArray(s.length / 2) { i ->
            s.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    } catch (_: NumberFormatException) {
        null
    }
}

/**
 * BigInteger.toByteArray() can include a leading 0x00 sign byte or be shorter than [length].
 * This pads/strips to exactly [length] bytes.
 */
private fun ByteArray.stripLeadingZeroPad(length: Int): ByteArray {
    return when {
        size == length -> this
        size > length  -> copyOfRange(size - length, size)   // strip sign byte(s)
        else           -> ByteArray(length - size) + this    // left-pad with zeros
    }
}
