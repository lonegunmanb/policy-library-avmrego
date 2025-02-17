package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azurerm_use_resilient_load_lalancer_sku(resource) if {
    resource.values.sku != "Basic"
}

deny_use_resilient_load_lalancer_sku contains reason if {
    resource := data.utils.resource(input, "azurerm_lb")[_]
    not valid_azurerm_use_resilient_load_lalancer_sku(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/use_resilient_load_lalancer_sku: '%s' `azurerm_lb` must not have 'sku' set to 'Basic': https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/loadBalancers/#use-standard-load-balancer-sku", [resource.address])
}