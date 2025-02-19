package checkov

import rego.v1

valid_azurerm_sql_server_no_public_access(resource) if {
    not (resource.values.start_ip_address == ["0.0.0.0"] or resource.values.start_ip_address == ["0.0.0.0/0"]) or not resource.values.end_ip_address == ["255.255.255.255"]
}

deny_CKV_AZURE_11 contains reason if {
    resource := data.utils.resource(input, "azurerm_mariadb_firewall_rule")[_]

    not valid_azurerm_sql_server_no_public_access(resource)
    reason := sprintf("checkov/CKV_AZURE_11: Ensure no SQL Databases allow ingress from 0.0.0.0/0 (ANY IP) %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SQLServerNoPublicAccess.py", [resource.address])
}

deny_CKV_AZURE_11 contains reason if {
    resource := data.utils.resource(input, "azurerm_sql_firewall_rule")[_]

    not valid_azurerm_sql_server_no_public_access(resource)
    reason := sprintf("checkov/CKV_AZURE_11: Ensure no SQL Databases allow ingress from 0.0.0.0/0 (ANY IP) %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SQLServerNoPublicAccess.py", [resource.address])
}

deny_CKV_AZURE_11 contains reason if {
    resource := data.utils.resource(input, "azurerm_postgresql_firewall_rule")[_]

    not valid_azurerm_sql_server_no_public_access(resource)
    reason := sprintf("checkov/CKV_AZURE_11: Ensure no SQL Databases allow ingress from 0.0.0.0/0 (ANY IP) %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SQLServerNoPublicAccess.py", [resource.address])
}

deny_CKV_AZURE_11 contains reason if {
    resource := data.utils.resource(input, "azurerm_mysql_firewall_rule")[_]

    not valid_azurerm_sql_server_no_public_access(resource)
    reason := sprintf("checkov/CKV_AZURE_11: Ensure no SQL Databases allow ingress from 0.0.0.0/0 (ANY IP) %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SQLServerNoPublicAccess.py", [resource.address])
}
