package checkov

import rego.v1

valid_azurerm_storage_account_default_network_access_deny(resource) if {
    resource.values.default_action == "Deny"
}

valid_azurerm_storage_account_network_rules_default_network_access_deny(resource) if {
    resource.values.network_rules[0].default_action == "Deny"
}

deny_CKV_AZURE_35 contains reason if {
    resource := data.utils.resource(input, "azurerm_storage_account")[_]
    not valid_azurerm_storage_account_default_network_access_deny(resource)
    reason := sprintf("checkov/CKV_AZURE_35: Ensure default network access rule for Storage Accounts is set to deny for azurerm_storage_account %s. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageAccountDefaultNetworkAccessDeny.py", [resource.address])
}

deny_CKV_AZURE_35 contains reason if {
    resource := data.utils.resource(input, "azurerm_storage_account_network_rules")[_]
    not valid_azurerm_storage_account_network_rules_default_network_access_deny(resource)
    reason := sprintf("checkov/CKV_AZURE_35: Ensure default network access rule for Storage Accounts is set to deny for azurerm_storage_account_network_rules %s. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageAccountDefaultNetworkAccessDeny.py", [resource.address])
}
