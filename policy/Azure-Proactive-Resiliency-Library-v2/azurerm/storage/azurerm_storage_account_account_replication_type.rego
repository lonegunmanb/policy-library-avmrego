package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azurerm_storage_accounts_are_zone_or_region_redundant(resource) if {
    resource.values.account_replication_type != "LRS"
}

deny_storage_accounts_are_zone_or_region_redundant contains reason if {
    resource := data.utils.resource(input, "azurerm_storage_account")[_]
    not valid_azurerm_storage_accounts_are_zone_or_region_redundant(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/storage_accounts_are_zone_or_region_redundant: '%s' `azurerm_storage_account` must not have 'account_replication_type' set to 'LRS': https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Storage/storageAccounts/#ensure-that-storage-accounts-are-zone-or-region-redundant", [resource.address])
}