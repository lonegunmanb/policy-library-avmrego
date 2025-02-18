package checkov

import rego.v1

valid_azurerm_security_center_subscription_pricing_is_on(resource) if {
    resource.resource_type != "KubernetesService"
}

valid_azurerm_security_center_subscription_pricing_is_on(resource) if {
    resource.tier == "Standard"
}

deny_azure_defender_on_kubernetes contains reason if {
    resource := input.resource.azurerm_security_center_subscription_pricing[_]
    not valid_azurerm_security_center_subscription_pricing_is_on(resource)

    reason := sprintf("checkov/CKV_AZURE_85: Ensure that Azure Defender is set to On for Kubernetes. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureDefenderOnKubernetes.py")
}
