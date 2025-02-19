package checkov

import rego.v1

valid_azurerm_keyvault_is_recoverable(resource) if {
    resource.values.purge_protection_enabled == true
    resource.values.soft_delete_enabled == true
}

valid_azurerm_keyvault_is_recoverable(resource) if {
    resource.values.purge_protection_enabled == true
    not resource.values.soft_delete_enabled == false
}

deny_CKV_AZURE_42 contains reason if {
    resource := data.utils.resource(input, "azurerm_key_vault")[_]
    not valid_azurerm_keyvault_is_recoverable(resource)

    reason := sprintf("checkov/CKV_AZURE_42: Ensure the key vault is recoverable: %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/KeyvaultRecoveryEnabled.py", [resource.address])
}
