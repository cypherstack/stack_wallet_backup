import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:stack_wallet_backup/stack_wallet_backup_method_channel.dart';

void main() {
  MethodChannelStackWalletBackup platform = MethodChannelStackWalletBackup();
  const MethodChannel channel = MethodChannel('stack_wallet_backup');

  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
      channel,
      (methodCall) async => '42',
    );
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
      channel,
      (methodCall) => null,
    );
  });

  test('getPlatformVersion', () async {
    expect(await platform.getPlatformVersion(), '42');
  });
}
