package Azure_Proactive_Resiliency_Library_v2.virtual_network_gateway_use_zone_redundant_sku

import rego.v1

valid_azapi_sku_name(resource) if {
   zone_redundant_skus := {"ErGw1AZ", "ErGw2AZ", "ErGw3AZ", "VpnGw1AZ", "VpnGw2AZ", "VpnGw3AZ", "VpnGw4AZ", "VpnGw5AZ"}
   zone_redundant_skus[resource.values.body.properties.sku.name]
}


deny_virtual_network_gateway_use_zone_redundant_sku contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.Network/virtualNetworkGateways")
    not valid_azapi_sku_name(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2: '%s' `azapi_resource` must have configured `sku.name` to one of {\"ErGw1AZ\", \"ErGw2AZ\", \"ErGw3AZ\", \"VpnGw1AZ\", \"VpnGw2AZ\", \"VpnGw3AZ\", \"VpnGw4AZ\", \"VpnGw5AZ\"}: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/virtualNetworkGateways/#use-zone-redundant-expressroute-gateway-skus", [resource.address])
}