package checkov

import rego.v1

valid_azurerm_service_fabric_cluster_protection_level(resource) if {
    settings := resource.values.fabric_settings[_]
    settings.name == ["Security"]
    params := settings.parameters[0]
    params.name == "ClusterProtectionLevel"
    params.value == "EncryptAndSign"
}

deny_azure_service_fabric_cluster_protection_level contains reason if {
    resource := data.utils.resource(input, "azurerm_service_fabric_cluster")[_]
    not valid_azurerm_service_fabric_cluster_protection_level(resource)

    reason := sprintf("checkov/CKV_AZURE_125: Ensure that Service Fabric use three levels of protection available. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureServiceFabricClusterProtectionLevel.py")
}
