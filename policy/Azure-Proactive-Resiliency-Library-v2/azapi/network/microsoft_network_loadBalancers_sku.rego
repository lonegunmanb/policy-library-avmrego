package Azure_Proactive_Resiliency_Library_v2.Microsoft_Network_loadBalancers

valid_sku(after) {
    after.body.sku.name
    after.body.sku.name != "Basic"
}

deny_use_resilient_load_lalancer_sku[reason] {
    tfplan := data.utils.tfplan(input)
    resource := tfplan.resource_changes[_]
    resource.mode == "managed"
    resource.type == "azapi_resource"
    data.utils.is_azure_type(resource.change.after, "Microsoft.Network/loadBalancers")
    data.utils.is_create_or_update(resource.change.actions)
    not valid_sku(resource.change.after)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2: '%s' `azapi_resource` must not have 'sku.name' set to 'Basic': https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/loadBalancers/#use-standard-load-balancer-sku", [resource.address])
}