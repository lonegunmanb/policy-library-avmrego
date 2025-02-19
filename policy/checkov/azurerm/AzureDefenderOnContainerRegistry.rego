package checkov

import rego.v1

valid_azurerm_security_center_subscription_pricing_is_standard(resource) if {
    resource.resource_type != "ContainerRegistry"
}

valid_azurerm_security_center_subscription_pricing_is_standard(resource) if {
    resource.tier == "Standard"
}

deny_CKV_AZURE_86 contains reason if {
    resource := input[_]
    resource.resource_type == "azurerm_security_center_subscription_pricing"
    not valid_azurerm_security_center_subscription_pricing_is_standard(resource.properties)

    reason := sprintf("checkov/CKV_AZURE_86: Ensure that Azure Defender is set to On for Container Registries %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureDefenderOnContainerRegistry.py", [resource.name])
}
