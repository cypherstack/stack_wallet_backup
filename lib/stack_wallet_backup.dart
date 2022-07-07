
import 'stack_wallet_backup_platform_interface.dart';

class StackWalletBackup {
  Future<String?> getPlatformVersion() {
    return StackWalletBackupPlatform.instance.getPlatformVersion();
  }
}
