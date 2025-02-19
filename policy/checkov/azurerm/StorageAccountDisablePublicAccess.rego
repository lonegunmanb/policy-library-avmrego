package checkov

import rego.v1

valid_azurerm_storage_account_no_public_access(resource) if {
    resource.values.allow_blob_public_access == false
}

deny_CKV_AZURE_59 contains reason if {
    resource := data.utils.resource(input, "azurerm_storage_account")[_]
    not valid_azurerm_storage_account_no_public_access(resource)

    reason := sprintf("checkov/CKV_AZURE_59: Ensure that Storage accounts disallow public access. Resource %s allows public access. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageAccountDisablePublicAccess.py", [resource.address])
}
