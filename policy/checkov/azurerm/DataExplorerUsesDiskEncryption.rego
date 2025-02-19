package checkov

import rego.v1

valid_azurerm_kusto_cluster_disk_encryption(resource) if {
    resource.values.enable_disk_encryption == true
}

deny_CKV_AZURE_74 contains reason if {
    resource := data.utils.resource(input, "azurerm_kusto_cluster")[_]
    not valid_azurerm_kusto_cluster_disk_encryption(resource)

    reason := sprintf("checkov/CKV_AZURE_74: Ensure that Azure Data Explorer uses disk encryption. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/DataExplorerUsesDiskEncryption.py")
}