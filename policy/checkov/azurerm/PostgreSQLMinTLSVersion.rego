package checkov

import rego.v1

valid_azurerm_postgresql_server_min_tls_version(resource) if {
    resource.values.ssl_minimal_tls_version_enforced == "TLS1_2"
}

deny_CKV_AZURE_147 contains reason if {
    resource := data.utils.resource(input, "azurerm_postgresql_server")[_]
    not valid_azurerm_postgresql_server_min_tls_version(resource)

    reason := sprintf("checkov/CKV_AZURE_147: Ensure PostgreSQL is using the latest version of TLS encryption. Resource %s must have ssl_minimal_tls_version_enforced set to TLS1_2. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/PostgreSQLMinTLSVersion.py", [resource.address])
}
