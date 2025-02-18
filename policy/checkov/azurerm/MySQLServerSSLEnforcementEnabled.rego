package checkov

import rego.v1

valid_azurerm_mysql_server_ssl_enabled(resource) if {
    resource.values.ssl_enforcement_enabled == true
}

deny contains reason if {
    resource := data.utils.resource(input, "azurerm_mysql_server")[_]
    not valid_azurerm_mysql_server_ssl_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_28: Ensure 'Enforce SSL connection' is set to 'ENABLED' for MySQL Database Server https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/MySQLServerSSLEnforcementEnabled.py")
}
