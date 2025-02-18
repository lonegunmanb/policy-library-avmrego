package checkov

import rego.v1

valid_azurerm_cosmosdb_account_restricted_access(resource) if {
    not resource.values.public_network_access_enabled
}

valid_azurerm_cosmosdb_account_restricted_access(resource) if {
    resource.values.public_network_access_enabled
    resource.values.is_virtual_network_filter_enabled

    resource.values.virtual_network_rule[_]
}

valid_azurerm_cosmosdb_account_restricted_access(resource) if {
    resource.values.public_network_access_enabled
    resource.values.is_virtual_network_filter_enabled
    resource.values.ip_range_filter[_]
}

deny_cosmosdb_accounts_restricted_access contains reason if {
    resource := data.utils.resource(input, "azurerm_cosmosdb_account")[_]
    not valid_azurerm_cosmosdb_account_restricted_access(resource)

    reason := sprintf("checkov/CKV_AZURE_99: Ensure Cosmos DB accounts have restricted access. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/CosmosDBAccountsRestrictedAccess.py")
}
