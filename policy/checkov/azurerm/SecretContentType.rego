package checkov

import rego.v1

valid_azurerm_key_vault_secret_has_content_type(resource) if {
    resource.values.content_type != null
}

deny_CKV_AZURE_114 contains reason if {
    resource := data.utils.resource(input, "azurerm_key_vault_secret")[_]
    not valid_azurerm_key_vault_secret_has_content_type(resource)

    reason := sprintf("checkov/CKV_AZURE_114: Ensure that key vault secrets have \"content_type\" set https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SecretContentType.py")
}
