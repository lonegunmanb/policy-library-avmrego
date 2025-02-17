package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azurerm_configure_cosmosdb_account_continuous_backup_mode(resource) if {
    resource.values.backup[_].type == "Continuous"
}

deny_configure_cosmosdb_account_continuous_backup_mode contains reason if {
    resource := data.utils.resource(input, "azurerm_cosmosdb_account")[_]
    not valid_azurerm_configure_cosmosdb_account_continuous_backup_mode(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/configure_cosmosdb_account_continuous_backup_mode: '%s' `azurerm_cosmosdb_account` must have backup type configured to 'Continuous': https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DocumentDB/databaseAccounts/#configure-continuous-backup-mode", [resource.address])
}