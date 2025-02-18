package checkov

import rego.v1

valid_azurerm_cosmosdb_have_cmk(resource) if {
    resource.values.key_vault_key_id != null
}

deny_cosmosdb_have_cmk contains reason if {
    resource := data.utils.resource(input, "azurerm_cosmosdb_account")[_]
    not valid_azurerm_cosmosdb_have_cmk(resource)

    reason := sprintf("checkov/CKV_AZURE_100: Ensure that Cosmos DB accounts have customer-managed keys to encrypt data at rest '%s' https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/CosmosDBHaveCMK.py", [resource.address])
}