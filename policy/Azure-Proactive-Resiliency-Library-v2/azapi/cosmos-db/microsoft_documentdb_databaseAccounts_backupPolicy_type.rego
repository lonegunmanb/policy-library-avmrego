package Azure_Proactive_Resiliency_Library_v2.Microsoft_Network_databaseAccounts

import rego.v1

valid_cosmosdb_account_backup_policy_type(resource) if {
    resource.values.body.properties.backupPolicy.type == "Continuous"
}

deny_configure_cosmosdb_account_continuous_backup_mode contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.DocumentDB/databaseAccounts")
    not valid_cosmosdb_account_backup_policy_type(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2: '%s' `azapi_resource` must have backup type configured to 'Continuous': https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DocumentDB/databaseAccounts/#configure-continuous-backup-mode", [resource.address])
}