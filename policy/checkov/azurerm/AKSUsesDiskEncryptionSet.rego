package checkov

import rego.v1

valid_azurerm_kubernetes_cluster_uses_disk_encryption_set(resource) if {
    resource.values.disk_encryption_set_id != null
}

deny_azurerm_kubernetes_cluster_uses_disk_encryption_set contains reason if {
    resource := data.utils.resource(input, "azurerm_kubernetes_cluster")[_]
    not valid_azurerm_kubernetes_cluster_uses_disk_encryption_set(resource)

    reason := sprintf("checkov/CKV_AZURE_117: Ensure that AKS uses disk encryption set. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSUsesDiskEncryptionSet.py")
}
