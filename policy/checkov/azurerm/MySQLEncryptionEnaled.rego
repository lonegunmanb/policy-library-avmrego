package checkov

import rego.v1

valid_azurerm_mysql_server_infrastructure_encryption_enabled(resource) if {
    resource.values.infrastructure_encryption_enabled == true
}

deny_CKV_AZURE_96 contains reason if {
    resource := data.utils.resource(input, "azurerm_mysql_server")[_]
    not valid_azurerm_mysql_server_infrastructure_encryption_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_96: Ensure that MySQL server enables infrastructure encryption. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/MySQLEncryptionEnaled.py")
}