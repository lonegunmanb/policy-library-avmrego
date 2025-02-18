package checkov

import rego.v1

valid_azurerm_cosmosdb_account_public_network_disabled(resource) if {
    resource.values.public_network_access_enabled == false
}

deny_cosmosdb_public_network contains reason if {
    resource := data.utils.resource(input, "azurerm_cosmosdb_account")[_]
    not valid_azurerm_cosmosdb_account_public_network_disabled(resource)

    reason := sprintf("checkov/CKV_AZURE_101: Ensure that Azure Cosmos DB disables public network access. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/CosmosDBDisablesPublicNetwork.py")
}
