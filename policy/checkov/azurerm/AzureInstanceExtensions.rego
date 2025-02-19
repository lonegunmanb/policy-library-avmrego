package checkov

import rego.v1

valid_azurerm_instance_extensions(resource) if {
    resource.values.allow_extension_operations == false
}

deny_CKV_AZURE_50 contains reason if {
    resource := data.utils.resource(input, "azurerm_linux_virtual_machine")[_]
	not valid_azurerm_instance_extensions(resource)
    reason := sprintf("checkov/CKV_AZURE_50: Ensure Virtual Machine Extensions are not Installed on azurerm_linux_virtual_machine. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureInstanceExtensions.py")
}

deny_CKV_AZURE_50 contains reason if {
    resource := data.utils.resource(input, "azurerm_windows_virtual_machine")[_]
	not valid_azurerm_instance_extensions(resource)
    reason := sprintf("checkov/CKV_AZURE_50: Ensure Virtual Machine Extensions are not Installed on azurerm_windows_virtual_machine. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureInstanceExtensions.py")
}