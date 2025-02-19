package checkov

import rego.v1

valid_azurerm_managed_disk_encryption_set_id(resource) if {
    resource.values.disk_encryption_set_id != null
}

deny_CKV_AZURE_93 contains reason if {
    resource := data.utils.resource(input, "azurerm_managed_disk")[_]
    not valid_azurerm_managed_disk_encryption_set_id(resource)

    reason := sprintf("checkov/CKV_AZURE_93: Ensure that managed disks use a specific set of disk encryption sets for the customer-managed key encryption %s", ["https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureManagedDiskEncryptionSet.py"])
}
