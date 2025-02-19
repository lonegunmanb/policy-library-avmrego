package checkov

import rego.v1

valid_azurerm_security_center_subscription_pricing_tier_is_standard(resource) if {
    resource.values.tier == "Standard"
}

deny_CKV_AZURE_19 contains reason if {
    resource := data.utils.resource(input, "azurerm_security_center_subscription_pricing")[_]
    not valid_azurerm_security_center_subscription_pricing_tier_is_standard(resource)

    reason := sprintf("checkov/CKV_AZURE_19: Ensure that standard pricing tier is selected for azurerm_security_center_subscription_pricing. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SecurityCenterStandardPricing.py")
}
