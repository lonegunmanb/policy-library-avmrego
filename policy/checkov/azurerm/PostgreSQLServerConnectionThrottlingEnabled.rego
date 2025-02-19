package checkov

import rego.v1

valid_azurerm_postgresql_configuration_connection_throttling(resource) if {
    resource.values.name == "connection_throttling"
    resource.values.value == "on"
}

deny_CKV_AZURE_32 contains reason if {
    resource := data.utils.resource(input, "azurerm_postgresql_configuration")[_]
    not valid_azurerm_postgresql_configuration_connection_throttling(resource)

    reason := sprintf("checkov/CKV_AZURE_32: Ensure server parameter 'connection_throttling' is set to 'ON' for PostgreSQL Database Server https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/PostgreSQLServerConnectionThrottlingEnabled.py")
}
