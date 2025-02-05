package Azure_Proactive_Resiliency_Library_v2.azurerm_lb

valid_sku(resource) {
    resource.change.after.sku != "Basic"
}

deny_use_resilient_load_lalancer_sku[reason] {
    tfplan := data.utils.tfplan(input)
    resource := tfplan.resource_changes[_]
    resource.mode == "managed"
    resource.type == "azurerm_lb"
    data.utils.is_create_or_update(resource.change.actions)
    not valid_sku(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2: '%s' `azurerm_lb` must not have 'sku' set to 'Basic': https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/loadBalancers/#use-standard-load-balancer-sku", [resource.address])
}