#ifndef FLUTTER_PLUGIN_STACK_WALLET_BACKUP_PLUGIN_H_
#define FLUTTER_PLUGIN_STACK_WALLET_BACKUP_PLUGIN_H_

#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>

#include <memory>

namespace stack_wallet_backup {

class StackWalletBackupPlugin : public flutter::Plugin {
 public:
  static void RegisterWithRegistrar(flutter::PluginRegistrarWindows *registrar);

  StackWalletBackupPlugin();

  virtual ~StackWalletBackupPlugin();

  // Disallow copy and assign.
  StackWalletBackupPlugin(const StackWalletBackupPlugin&) = delete;
  StackWalletBackupPlugin& operator=(const StackWalletBackupPlugin&) = delete;

 private:
  // Called when a method is called on this plugin's channel from Dart.
  void HandleMethodCall(
      const flutter::MethodCall<flutter::EncodableValue> &method_call,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
};

}  // namespace stack_wallet_backup

#endif  // FLUTTER_PLUGIN_STACK_WALLET_BACKUP_PLUGIN_H_
