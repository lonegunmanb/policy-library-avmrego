package checkov

import rego.v1

valid_azurerm_key_vault_secret_has_expiration_date(resource) if {
    resource.values.expiration_date != null
}

deny_CKV_AZURE_41 contains reason if {
    resource := data.utils.resource(input, "azurerm_key_vault_secret")[_]
    not valid_azurerm_key_vault_secret_has_expiration_date(resource)

    reason := sprintf("checkov/CKV_AZURE_41: Ensure that the expiration date is set on all secrets. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SecretExpirationDate.py", [])
}
