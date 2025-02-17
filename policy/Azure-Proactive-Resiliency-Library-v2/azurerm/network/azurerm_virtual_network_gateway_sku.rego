package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azurerm_virtual_network_gateway_use_zone_redundant_sku(resource) if {
   zone_redundant_skus := {"ErGw1AZ", "ErGw2AZ", "ErGw3AZ", "VpnGw1AZ", "VpnGw2AZ", "VpnGw3AZ", "VpnGw4AZ", "VpnGw5AZ"}
   zone_redundant_skus[resource.values.sku]
}

deny_virtual_network_gateway_use_zone_redundant_sku contains reason if {
    resource := data.utils.resource(input, "azurerm_virtual_network_gateway")[_]
    not valid_azurerm_virtual_network_gateway_use_zone_redundant_sku(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/virtual_network_gateway_use_zone_redundant_sku: '%s' `azurerm_virtual_network_gateway` must have configured `sku` to one of {\"ErGw1AZ\", \"ErGw2AZ\", \"ErGw3AZ\", \"VpnGw1AZ\", \"VpnGw2AZ\", \"VpnGw3AZ\", \"VpnGw4AZ\", \"VpnGw5AZ\"}: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/virtualNetworkGateways/#use-zone-redundant-expressroute-gateway-skus", [resource.address])
}