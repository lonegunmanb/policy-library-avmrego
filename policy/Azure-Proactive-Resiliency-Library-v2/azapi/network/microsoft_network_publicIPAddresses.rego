package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azapi_use_standard_sku_and_zone_redundant_ip(resource) if {
    resource.values.body.sku.name == "Sandard"
    count(resource.values.body.zones) >= 2
}

deny_use_standard_sku_and_zone_redundant_ip contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.Network/publicIPAddresses")
    not valid_azapi_use_standard_sku_and_zone_redundant_ip(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/use_standard_sku_and_zone_redundant_ip: '%s' `azapi_resource` must have configured `sku.name` to `\"Standard\"` and a `zones` that cotnains at least 2 zones: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/publicIPAddresses/#use-standard-sku-and-zone-redundant-ips-when-applicable", [resource.address])
}