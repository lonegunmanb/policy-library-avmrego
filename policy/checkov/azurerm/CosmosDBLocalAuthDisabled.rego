package checkov

import rego.v1

valid_azurerm_cosmosdb_local_auth_disabled(resource) if {
    resource.values.local_authentication_disabled == true
}

deny_cosmosdb_local_auth_disabled contains reason if {
    resource := data.utils.resource(input, "azurerm_cosmosdb_account")[_]
    not valid_azurerm_cosmosdb_local_auth_disabled(resource)

    reason := sprintf("checkov/CKV_AZURE_140: Ensure that Local Authentication is disabled on CosmosDB. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/CosmosDBLocalAuthDisabled.py")
}