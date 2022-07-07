import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'stack_wallet_backup_method_channel.dart';

abstract class StackWalletBackupPlatform extends PlatformInterface {
  /// Constructs a StackWalletBackupPlatform.
  StackWalletBackupPlatform() : super(token: _token);

  static final Object _token = Object();

  static StackWalletBackupPlatform _instance = MethodChannelStackWalletBackup();

  /// The default instance of [StackWalletBackupPlatform] to use.
  ///
  /// Defaults to [MethodChannelStackWalletBackup].
  static StackWalletBackupPlatform get instance => _instance;
  
  /// Platform-specific implementations should set this with their own
  /// platform-specific class that extends [StackWalletBackupPlatform] when
  /// they register themselves.
  static set instance(StackWalletBackupPlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  Future<String?> getPlatformVersion() {
    throw UnimplementedError('platformVersion() has not been implemented.');
  }
}
