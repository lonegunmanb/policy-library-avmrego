package checkov

import rego.v1

valid_azurerm_security_center_subscription_pricing_defender_on(resource) if {
    resource.resource_type != "KeyVaults"
}

valid_azurerm_security_center_subscription_pricing_defender_on(resource) if {
    resource.tier == "Standard"
}

deny_azure_defender_on_key_vaults contains reason if {
    resource := input.resource.azurerm_security_center_subscription_pricing[_]
    not valid_azurerm_security_center_subscription_pricing_defender_on(resource)

    reason := sprintf("checkov/CKV_AZURE_87: Ensure that Azure Defender is set to On for Key Vault. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureDefenderOnKeyVaults.py")
}
