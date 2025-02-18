package checkov

import rego.v1

valid_azurerm_security_center_subscription_pricing_tier(resource) if {
    resource.values.resource_type != "AppServices"
}

valid_azurerm_security_center_subscription_pricing_tier(resource) if {
    resource.values.tier == "Standard"
}

deny_azure_defender_on_app_services contains reason if {
    resource := data.utils.resource(input, "azurerm_security_center_subscription_pricing")[_]
    not valid_azurerm_security_center_subscription_pricing_tier(resource)

    reason := sprintf("checkov/CKV_AZURE_61: Ensure that Azure Defender is set to On for App Service. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureDefenderOnAppServices.py")
}
