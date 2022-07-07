#import "StackWalletBackupPlugin.h"
#if __has_include(<stack_wallet_backup/stack_wallet_backup-Swift.h>)
#import <stack_wallet_backup/stack_wallet_backup-Swift.h>
#else
// Support project import fallback if the generated compatibility header
// is not copied when this plugin is created as a library.
// https://forums.swift.org/t/swift-static-libraries-dont-copy-generated-objective-c-header/19816
#import "stack_wallet_backup-Swift.h"
#endif

@implementation StackWalletBackupPlugin
+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
  [SwiftStackWalletBackupPlugin registerWithRegistrar:registrar];
}
@end
