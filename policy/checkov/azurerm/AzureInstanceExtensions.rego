package checkov

import rego.v1

valid_azurerm_vm_extension_operations_disabled(resource) if {
    resource.values.allow_extension_operations == false
}

deny_vm_extension_operations_enabled contains reason if {
    resource := data.utils.resource(input, "azurerm_linux_virtual_machine")[_]
    not valid_azurerm_vm_extension_operations_disabled(resource)
    reason := sprintf("checkov/CKV_AZURE_50: Ensure Virtual Machine Extensions are not Installed for azurerm_linux_virtual_machine. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureInstanceExtensions.py")
}

deny_vm_extension_operations_enabled contains reason if {
    resource := data.utils.resource(input, "azurerm_windows_virtual_machine")[_]
    not valid_azurerm_vm_extension_operations_disabled(resource)
    reason := sprintf("checkov/CKV_AZURE_50: Ensure Virtual Machine Extensions are not Installed for azurerm_windows_virtual_machine. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureInstanceExtensions.py")
}