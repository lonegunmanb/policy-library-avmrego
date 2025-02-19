package checkov

import rego.v1

valid_azurerm_managed_disk_encryption(resource) if {
    resource.disk_encryption_set_id != null
}

valid_azurerm_managed_disk_encryption(resource) if {
    resource.encryption_settings != null
    resource.encryption_settings[0].enabled == true
}

deny_CKV_AZURE_2 contains reason if {
    resource := input.resource.azurerm_managed_disk[_]
    not valid_azurerm_managed_disk_encryption(resource)

    reason := sprintf("checkov/CKV_AZURE_2: Ensure Azure managed disk has encryption enabled. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureManagedDiskEncryption.py")
}
