package Azure_Proactive_Resiliency_Library_v2.azurerm_cosmosdb_account

valid_cosmosdb_account_backup_policy_type(after) if {
    after.backup[_].type == "Continuous"
}

deny_configure_cosmosdb_account_continuous_backup_mode contains reason if {
    tfplan := data.utils.tfplan(input)
    resource := tfplan.resource_changes[_]
    resource.mode == "managed"
    resource.type == "azurerm_cosmosdb_account"
    data.utils.is_create_or_update(resource.change.actions)
    not valid_cosmosdb_account_backup_policy_type(resource.change.after)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2: '%s' `azurerm_cosmosdb_account` must have backup type configured to 'Continuous': https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DocumentDB/databaseAccounts/#configure-continuous-backup-mode", [resource.address])
}