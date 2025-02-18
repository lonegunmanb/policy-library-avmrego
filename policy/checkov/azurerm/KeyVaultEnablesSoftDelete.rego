package checkov

import rego.v1

valid_azurerm_keyvault_soft_delete_enabled(resource) if {
    resource.values.soft_delete_enabled == true
}

deny_keyvault_soft_delete contains reason if {
    resource := data.utils.resource(input, "azurerm_key_vault")[_]
    not valid_azurerm_keyvault_soft_delete_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_111: Ensure that key vault enables soft delete %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/KeyVaultEnablesSoftDelete.py", [resource.address])
}
