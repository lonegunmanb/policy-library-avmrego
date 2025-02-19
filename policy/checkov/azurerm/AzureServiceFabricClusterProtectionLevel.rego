package checkov

import rego.v1

valid_azurerm_service_fabric_cluster_protection_level(resource) if {
    fabric_settings := resource.values.fabric_settings
    some(setting; fabric_settings)
    setting.name == ["Security"]
    params := setting.parameters[0]
    params.name == "ClusterProtectionLevel"
    params.value == "EncryptAndSign"
}

deny_CKV_AZURE_125 contains reason if {
    resource := data.utils.resource(input, "azurerm_service_fabric_cluster")[_]
    not valid_azurerm_service_fabric_cluster_protection_level(resource)

    reason := sprintf("checkov/CKV_AZURE_125: Ensures that Service Fabric use three levels of protection available. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureServiceFabricClusterProtectionLevel.py")
}
