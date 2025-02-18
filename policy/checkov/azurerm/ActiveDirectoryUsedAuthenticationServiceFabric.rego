package checkov

import rego.v1

valid_azurerm_service_fabric_cluster_has_active_directory(resource) if {
    resource.values.azure_active_directory[0].tenant_id != null
}

deny_CKV_AZURE_126 contains reason if {
    resource := data.utils.resource(input, "azurerm_service_fabric_cluster")[_]
    not valid_azurerm_service_fabric_cluster_has_active_directory(resource)

    reason := sprintf("checkov/CKV_AZURE_126: Ensure that Active Directory is used for authentication for Service Fabric %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/ActiveDirectoryUsedAuthenticationServiceFabric.py", [resource.address])
}
