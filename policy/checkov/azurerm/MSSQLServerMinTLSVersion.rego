package checkov

import rego.v1

valid_azurerm_mssql_server_min_tls_version(resource) if {
    resource.values.minimum_tls_version == "1.2"
}

deny_CKV_AZURE_52 contains reason if {
    resource := data.utils.resource(input, "azurerm_mssql_server")[_]
    not valid_azurerm_mssql_server_min_tls_version(resource)

    reason := sprintf("checkov/CKV_AZURE_52: Ensure MSSQL is using the latest version of TLS encryption. Resource %s is not using TLS version 1.2 https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/MSSQLServerMinTLSVersion.py", [resource.address])
}
