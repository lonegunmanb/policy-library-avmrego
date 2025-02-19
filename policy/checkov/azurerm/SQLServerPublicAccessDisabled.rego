package checkov

import rego.v1

valid_azurerm_mssql_server_public_access_disabled(resource) if {
    resource.values.public_network_access_enabled == false
}

deny_CKV_AZURE_113 contains reason if {
    resource := data.utils.resource(input, "azurerm_mssql_server")[_]
    not valid_azurerm_mssql_server_public_access_disabled(resource)

    reason := sprintf("checkov/CKV_AZURE_113: Ensure that SQL server disables public network access. Resource %s must have 'public_network_access_enabled' set to false. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SQLServerPublicAccessDisabled.py", [resource.address])
}
