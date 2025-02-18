package checkov

import rego.v1

valid_azurerm_container_registry_defender_enabled(resource) if {
    resource.values.resource_type != "ContainerRegistry"
}

valid_azurerm_container_registry_defender_enabled(resource) if {
    resource.values.tier == "Standard"
}

deny_azure_defender_on_container_registry contains reason if {
    resource := data.utils.resource(input, "azurerm_security_center_subscription_pricing")[_]
    not valid_azurerm_container_registry_defender_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_86: Ensure that Azure Defender is set to On for Container Registries https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureDefenderOnContainerRegistry.py")
}
