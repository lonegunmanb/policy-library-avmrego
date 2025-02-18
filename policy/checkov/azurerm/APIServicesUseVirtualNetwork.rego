package checkov

import rego.v1

valid_azurerm_api_management_in_virtual_network(resource) if {
    resource.values.virtual_network_configuration[0].subnet_id != null
}

deny_CKV_AZURE_107 contains reason if {
    resource := data.utils.resource(input, "azurerm_api_management")[_]
    not valid_azurerm_api_management_in_virtual_network(resource)

    reason := sprintf("checkov/CKV_AZURE_107: Ensure that API management services use virtual networks. Resource %s is not deployed in a virtual network. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/APIServicesUseVirtualNetwork.py", [resource.address])
}
