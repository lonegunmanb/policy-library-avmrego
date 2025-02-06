package Azure_Proactive_Resiliency_Library_v2.Microsoft_Network_databaseAccounts

valid_cosmosdb_account_backup_policy_type(after) if {
    after.body.properties.backupPolicy.type == "Continuous"
}

deny_configure_cosmosdb_account_continuous_backup_mode[reason] if {
    tfplan := data.utils.tfplan(input)
    resource := tfplan.resource_changes[_]
    resource.mode == "managed"
    resource.type == "azapi_resource"
    data.utils.is_azure_type(resource.change.after, "Microsoft.DocumentDB/databaseAccounts")
    data.utils.is_create_or_update(resource.change.actions)
    not valid_cosmosdb_account_backup_policy_type(resource.change.after)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2: '%s' `azapi_resource` must have backup type configured to 'Continuous': https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DocumentDB/databaseAccounts/#configure-continuous-backup-mode", [resource.address])
}