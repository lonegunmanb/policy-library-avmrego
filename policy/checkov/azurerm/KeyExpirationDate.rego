package checkov

import rego.v1

valid_azurerm_key_vault_key_has_expiration_date(resource) if {
    resource.values.expiration_date != null
}

deny_key_vault_key_missing_expiration_date contains reason if {
    resource := data.utils.resource(input, "azurerm_key_vault_key")[_]
    not valid_azurerm_key_vault_key_has_expiration_date(resource)

    reason := sprintf("checkov/CKV_AZURE_40: Ensure that the expiration date is set on all keys. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/KeyExpirationDate.py")
}
