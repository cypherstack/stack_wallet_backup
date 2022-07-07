import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'stack_wallet_backup_platform_interface.dart';

/// An implementation of [StackWalletBackupPlatform] that uses method channels.
class MethodChannelStackWalletBackup extends StackWalletBackupPlatform {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('stack_wallet_backup');

  @override
  Future<String?> getPlatformVersion() async {
    final version = await methodChannel.invokeMethod<String>('getPlatformVersion');
    return version;
  }
}
