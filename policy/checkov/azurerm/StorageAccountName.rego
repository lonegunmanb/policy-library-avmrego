package checkov

import rego.v1

valid_azurerm_storage_account_name(resource) if {
    name := resource.values.name
    re_match("^[a-z0-9]{3,24}$", name)
}

deny_CKV_AZURE_43 contains reason if {
    resource := data.utils.resource(input, "azurerm_storage_account")[_]
    not valid_azurerm_storage_account_name(resource)

    reason := sprintf("checkov/CKV_AZURE_43: Storage Account %s does not adhere to the naming rules: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageAccountName.py", [resource.address])
}
