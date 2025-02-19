package checkov

import rego.v1

valid_azurerm_postgresql_log_retention_enabled(resource) if {
    resource.values.name == ["log_retention"]
    resource.values.value == ["on"]
}

deny_CKV_AZURE_146 contains reason if {
    resource := data.utils.resource(input, "azurerm_postgresql_configuration")[_]
    not valid_azurerm_postgresql_log_retention_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_146: Ensure server parameter 'log_retention' is set to 'ON' for PostgreSQL Database Server https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/PostgreSQLServerLogRetentionEnabled.py")
}
