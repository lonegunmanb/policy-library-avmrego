package checkov

import rego.v1

valid_azurerm_batch_account_uses_key_vault_encryption(resource) if {
    resource.values.key_vault_reference != null
    count(resource.values.key_vault_reference) > 0
    resource.values.key_vault_reference[0].id != null
}

deny_azure_batch_account_uses_key_vault_encryption contains reason if {
    resource := data.utils.resource(input, "azurerm_batch_account")[_]
    not valid_azurerm_batch_account_uses_key_vault_encryption(resource)

    reason := sprintf("checkov/CKV_AZURE_76: Ensure that Azure Batch account uses key vault to encrypt data https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureBatchAccountUsesKeyVaultEncryption.py")
}
