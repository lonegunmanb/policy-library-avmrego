package checkov

import rego.v1

valid_azurerm_key_vault_key_backed_by_hsm(resource) if {
    resource.values.key_type == "RSA-HSM"
}

valid_azurerm_key_vault_key_backed_by_hsm(resource) if {
    resource.values.key_type == "EC-HSM"
}

deny_key_vault_key_backed_by_hsm contains reason if {
    resource := data.utils.resource(input, "azurerm_key_vault_key")[_]
    not valid_azurerm_key_vault_key_backed_by_hsm(resource)

    reason := sprintf("checkov/CKV_AZURE_112: Ensure that key vault key is backed by HSM. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/KeyBackedByHSM.py")
}
