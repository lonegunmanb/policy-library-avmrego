package checkov

import rego.v1

valid_azurerm_storage_account_azure_services_access_enabled(resource) if {
    not resource.values.network_rules
}

valid_azurerm_storage_account_azure_services_access_enabled(resource) if {
    resource.values.network_rules[_].default_action == "Allow"
}

valid_azurerm_storage_account_azure_services_access_enabled(resource) if {
    resource.values.network_rules[_].default_action == "Deny"
    "AzureServices" in resource.values.network_rules[_].bypass
}

deny_CKV_AZURE_36 contains reason if {
    resource := data.utils.resource(input, "azurerm_storage_account")[_]
    not valid_azurerm_storage_account_azure_services_access_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_36: Ensure 'Trusted Microsoft Services' is enabled for Storage Account access %s", [resource.address])
}

deny_CKV_AZURE_36 contains reason if {
    resource := data.utils.resource(input, "azurerm_storage_account_network_rules")[_]
    not valid_azurerm_storage_account_azure_services_access_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_36: Ensure 'Trusted Microsoft Services' is enabled for Storage Account access %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageAccountAzureServicesAccessEnabled.py", [resource.address])
}
