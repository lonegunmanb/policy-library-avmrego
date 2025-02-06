package Azure_Proactive_Resiliency_Library_v2.Microsoft_Network_loadBalancers

valid_outbound_rules(after) if {
    count(after.body.properties.outboundRules) == 0
}

valid_outbound_rules(after) if {
    not after.body.properties.outboundRules
}

deny_use_nat_gateway_instead_of_outbound_rules_for_production_load_lalancer[reason] if {
    tfplan := data.utils.tfplan(input)
    resource := tfplan.resource_changes[_]
    resource.mode == "managed"
    resource.type == "azapi_resource"
    data.utils.is_azure_type(resource.change.after, "Microsoft.Network/loadBalancers")
    data.utils.is_create_or_update(resource.change.actions)
    not valid_outbound_rules(resource.change.after)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2: '%s' `azapi_resource` must not config `outboundRules. Outbound rules for Standard Public Load Balancer involve manual port allocation for backend pools, limiting scalability and risk of SNAT port exhaustion. NAT Gateway is recommended for its dynamic scaling and secure internet connectivity.: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/loadBalancers/#use-nat-gateway-instead-of-outbound-rules-for-production-workloads", [resource.address])
}