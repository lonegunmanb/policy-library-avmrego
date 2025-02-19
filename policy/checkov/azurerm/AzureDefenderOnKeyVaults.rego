package checkov

import rego.v1

valid_azurerm_security_center_subscription_pricing_defender_on_keyvaults(resource) if {
    resource.values.resource_type != "KeyVaults"
}

valid_azurerm_security_center_subscription_pricing_defender_on_keyvaults(resource) if {
    resource.values.tier == "Standard"
}

deny_CKV_AZURE_87 contains reason if {
    resource := data.utils.resource(input, "azurerm_security_center_subscription_pricing")[_]
    not valid_azurerm_security_center_subscription_pricing_defender_on_keyvaults(resource)

    reason := sprintf("checkov/CKV_AZURE_87: Ensure that Azure Defender is set to On for Key Vault. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureDefenderOnKeyVaults.py")
}
