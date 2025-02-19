package checkov

import rego.v1

valid_azurerm_mysql_server_min_tls_version(resource) if {
    resource.values.ssl_minimal_tls_version_enforced == "TLS1_2"
}

deny_CKV_AZURE_54 contains reason if {
    resource := data.utils.resource(input, "azurerm_mysql_server")[_]
    not valid_azurerm_mysql_server_min_tls_version(resource)

    reason := sprintf("checkov/CKV_AZURE_54: Ensure MySQL is using the latest version of TLS encryption. Expected TLS1_2, got %v. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/MySQLServerMinTLSVersion.py", [resource.values.ssl_minimal_tls_version_enforced])
}
