package checkov

import rego.v1

valid_azurerm_mysql_public_access_disabled(resource) if {
    resource.values.public_network_access_enabled == false
}

deny_CKV_AZURE_53 contains reason if {
    resource := data.utils.resource(input, "azurerm_mysql_server")[_]
    not valid_azurerm_mysql_public_access_disabled(resource)

    reason := sprintf("checkov/CKV_AZURE_53: Ensure 'public network access enabled' is set to 'False' for mySQL servers. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/MySQLPublicAccessDisabled.py", [])
}