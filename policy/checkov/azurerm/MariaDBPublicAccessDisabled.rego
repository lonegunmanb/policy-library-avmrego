package checkov

import rego.v1

valid_azurerm_mariadb_server_public_access_disabled(resource) if {
    resource.values.public_network_access_enabled == false
}

deny_mariadb_public_access_enabled contains reason if {
    resource := data.utils.resource(input, "azurerm_mariadb_server")[_]
    not valid_azurerm_mariadb_server_public_access_disabled(resource)

    reason := sprintf("checkov/CKV_AZURE_48: Ensure 'public network access enabled' is set to 'False' for MariaDB servers: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/MariaDBPublicAccessDisabled.py")
}
