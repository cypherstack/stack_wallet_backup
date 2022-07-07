import 'package:flutter_test/flutter_test.dart';
import 'package:stack_wallet_backup/stack_wallet_backup.dart';
import 'package:stack_wallet_backup/stack_wallet_backup_platform_interface.dart';
import 'package:stack_wallet_backup/stack_wallet_backup_method_channel.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

class MockStackWalletBackupPlatform 
    with MockPlatformInterfaceMixin
    implements StackWalletBackupPlatform {

  @override
  Future<String?> getPlatformVersion() => Future.value('42');
}

void main() {
  final StackWalletBackupPlatform initialPlatform = StackWalletBackupPlatform.instance;

  test('$MethodChannelStackWalletBackup is the default instance', () {
    expect(initialPlatform, isInstanceOf<MethodChannelStackWalletBackup>());
  });

  test('getPlatformVersion', () async {
    StackWalletBackup stackWalletBackupPlugin = StackWalletBackup();
    MockStackWalletBackupPlatform fakePlatform = MockStackWalletBackupPlatform();
    StackWalletBackupPlatform.instance = fakePlatform;
  
    expect(await stackWalletBackupPlugin.getPlatformVersion(), '42');
  });
}
