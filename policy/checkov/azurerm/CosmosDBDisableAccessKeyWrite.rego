package checkov

import rego.v1

valid_azurerm_cosmosdb_access_key_metadata_writes_enabled(resource) if {
    resource.values.access_key_metadata_writes_enabled == false
}

deny_CKV_AZURE_132 contains reason if {
    resource := data.utils.resource(input, "azurerm_cosmosdb_account")[_]
    not valid_azurerm_cosmosdb_access_key_metadata_writes_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_132: Ensure cosmosdb does not allow privileged escalation by restricting management plane changes. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/CosmosDBDisableAccessKeyWrite.py")
}
