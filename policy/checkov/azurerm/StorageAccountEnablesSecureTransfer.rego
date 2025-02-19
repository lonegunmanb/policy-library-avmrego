package checkov

import rego.v1

valid_azurerm_storage_account_enables_secure_transfer(resource) if {
    resource.values.enable_https_traffic_only == true
}

deny_CKV_AZURE_60 contains reason if {
    resource := data.utils.resource(input, "azurerm_storage_account")[_]
    not valid_azurerm_storage_account_enables_secure_transfer(resource)

    reason := sprintf("checkov/CKV_AZURE_60: Ensure that storage account enables secure transfer %s", [resource.address])
}
