package checkov

import rego.v1

valid_azurerm_container_group_is_in_vnet(resource) if {
    resource.values.network_profile_id != null
}

deny_container_group_not_in_vnet contains reason if {
    resource := data.utils.resource(input, "azurerm_container_group")[_]
    not valid_azurerm_container_group_is_in_vnet(resource)

    reason := sprintf("checkov/CKV_AZURE_98: Ensure that Azure Container group is deployed into virtual network. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureContainerGroupDeployedIntoVirtualNetwork.py")
}
