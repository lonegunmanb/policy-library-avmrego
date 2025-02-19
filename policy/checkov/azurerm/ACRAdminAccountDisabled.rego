package checkov

import rego.v1

valid_azurerm_container_registry_admin_account_disabled(resource) if {
    resource.values.admin_enabled == false
}

deny_CKV_AZURE_137 contains reason if {
    resource := data.utils.resource(input, "azurerm_container_registry")[_]
    not valid_azurerm_container_registry_admin_account_disabled(resource)

    reason := sprintf("checkov/CKV_AZURE_137: Ensure ACR admin account is disabled %s", ["https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/ACRAdminAccountDisabled.py"])
}
