package Azure_Proactive_Resiliency_Library_v2.use_resilient_load_lalancer_sku

import rego.v1

valid_azapi_sku(resource) if {
    resource.values.body.sku.name
    resource.values.body.sku.name != "Basic"
}

deny_use_resilient_load_lalancer_sku contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.Network/loadBalancers")
    not valid_azapi_sku(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2: '%s' `azapi_resource` must not have 'sku.name' set to 'Basic': https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/loadBalancers/#use-standard-load-balancer-sku", [resource.address])
}