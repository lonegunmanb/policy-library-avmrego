package Azure_Proactive_Resiliency_Library_v2.use_nat_gateway_instead_of_outbound_rules_for_production_load_lalancer

import rego.v1

deny_use_nat_gateway_instead_of_outbound_rules_for_production_load_lalancer contains reason if {
    resources := data.utils.resource(input, "azurerm_lb_outbound_rule")
    count(resources) > 0
    reason := sprintf("Azure-Proactive-Resiliency-Library-v2: '%s' `azurerm_lb_outbound_rule` must not be used for production workloads: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/loadBalancers/#use-nat-gateway-instead-of-outbound-rules-for-production-workloads", [resource.address])
}