package checkov

import rego.v1

valid_azurerm_api_management_use_virtual_network(resource) if {
    resource.values.virtual_network_configuration[0].subnet_id != null
}

deny_api_management_services_use_virtual_networks contains reason if {
    resource := data.utils.resource(input, "azurerm_api_management")[_]
    not valid_azurerm_api_management_use_virtual_network(resource)

    reason := sprintf("checkov/CKV_AZURE_107: API management service %s should use virtual networks. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/APIServicesUseVirtualNetwork.py", [resource.address])
}
