/// On-chain device registration record, mirroring the Rust `DeviceRegistration`.
class DeviceInfo {
  final String deviceId;
  final String walletAddress;
  final String platform; // "ios" | "android"
  final int registeredAtHeight;

  const DeviceInfo({
    required this.deviceId,
    required this.walletAddress,
    required this.platform,
    required this.registeredAtHeight,
  });

  factory DeviceInfo.fromJson(Map<String, dynamic> json) {
    return DeviceInfo(
      deviceId: json['deviceId'] as String,
      walletAddress: json['walletAddress'] as String,
      platform: json['platform'] as String,
      registeredAtHeight: (json['registeredAtHeight'] as num).toInt(),
    );
  }
}
