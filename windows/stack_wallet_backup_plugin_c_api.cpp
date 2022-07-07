#include "include/stack_wallet_backup/stack_wallet_backup_plugin_c_api.h"

#include <flutter/plugin_registrar_windows.h>

#include "stack_wallet_backup_plugin.h"

void StackWalletBackupPluginCApiRegisterWithRegistrar(
    FlutterDesktopPluginRegistrarRef registrar) {
  stack_wallet_backup::StackWalletBackupPlugin::RegisterWithRegistrar(
      flutter::PluginRegistrarManager::GetInstance()
          ->GetRegistrar<flutter::PluginRegistrarWindows>(registrar));
}
