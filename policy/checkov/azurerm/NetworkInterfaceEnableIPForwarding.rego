package checkov

import rego.v1

valid_azurerm_network_interface_disable_ip_forwarding(resource) if {
    resource.values.enable_ip_forwarding == false
}

deny_CKV_AZURE_118 contains reason if {
    resource := data.utils.resource(input, "azurerm_network_interface")[_]
    not valid_azurerm_network_interface_disable_ip_forwarding(resource)

    reason := sprintf("checkov/CKV_AZURE_118: Ensure that Network Interfaces disable IP forwarding. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/NetworkInterfaceEnableIPForwarding.py")
}
