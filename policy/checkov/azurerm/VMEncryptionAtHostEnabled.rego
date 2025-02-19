package checkov

import rego.v1

valid_azurerm_vm_encryption_at_host_enabled(resource) if {
    resource.values.encryption_at_host_enabled == true
}

deny_CKV_AZURE_97 contains reason if {
    resource := data.utils.resource(input, "azurerm_linux_virtual_machine_scale_set")[_]
    not valid_azurerm_vm_encryption_at_host_enabled(resource)
    reason := sprintf("checkov/CKV_AZURE_97: Ensure that Virtual machine scale sets have encryption at host enabled for azurerm_linux_virtual_machine_scale_set. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/VMEncryptionAtHostEnabled.py")
}

deny_CKV_AZURE_97 contains reason if {
    resource := data.utils.resource(input, "azurerm_windows_virtual_machine_scale_set")[_]
    not valid_azurerm_vm_encryption_at_host_enabled(resource)
    reason := sprintf("checkov/CKV_AZURE_97: Ensure that Virtual machine scale sets have encryption at host enabled for azurerm_windows_virtual_machine_scale_set. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/VMEncryptionAtHostEnabled.py")
}
