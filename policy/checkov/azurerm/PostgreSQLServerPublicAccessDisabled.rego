package checkov

import rego.v1

valid_azurerm_postgresql_server_public_access_disabled(resource) if {
    resource.values.public_network_access_enabled == false
}

deny_CKV_AZURE_68 contains reason if {
    resource := data.utils.resource(input, "azurerm_postgresql_server")[_]
    not valid_azurerm_postgresql_server_public_access_disabled(resource)

    reason := sprintf("checkov/CKV_AZURE_68: Ensure that PostgreSQL server disables public network access. Resource %s has public network access enabled. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/PostgreSQLServerPublicAccessDisabled.py", [resource.address])
}
