package checkov

import rego.v1

valid_azurerm_windows_virtual_machine_encryption_at_host(resource) if {
    resource.values.encryption_at_host_enabled == true
}

deny_CKV_AZURE_151 contains reason if {
    resource := data.utils.resource(input, "azurerm_windows_virtual_machine")[_]
    not valid_azurerm_windows_virtual_machine_encryption_at_host(resource)

    reason := sprintf("checkov/CKV_AZURE_151: Ensure Windows VM enables encryption. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/WinVMEncryptionAtHost.py", {})
}
