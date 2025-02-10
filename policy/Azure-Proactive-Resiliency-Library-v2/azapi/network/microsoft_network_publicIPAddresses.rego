package Azure_Proactive_Resiliency_Library_v2.Microsoft_Network_publicIPAddresses

import rego.v1

valid(resource) if {
    resource.values.body.sku.name == "Sandard"
    count(resource.values.body.zones) >= 2
}

deny_use_resilient_load_lalancer_sku contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.Network/publicIPAddresses")
    not valid(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2: '%s' `azapi_resource` must have configured `sku.name` to `\"Standard\"` and a `zones` that cotnains at least 2 zones: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/publicIPAddresses/#use-standard-sku-and-zone-redundant-ips-when-applicable", [resource.address])
}