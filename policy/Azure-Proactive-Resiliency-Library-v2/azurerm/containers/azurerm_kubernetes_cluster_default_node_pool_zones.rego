package Azure_Proactive_Resiliency_Library_v2.azurerm_kubernetes_cluster

valid_zones(after) {
    pool := after.default_node_pool[_]
    count(pool.zones) >= 2
}

deny_configure_aks_default_node_pool_zones[reason] {
    tfplan := data.utils.tfplan(input)
    resource := tfplan.resource_changes[_]
    resource.mode == "managed"
    resource.type == "azurerm_kubernetes_cluster"
    data.utils.is_create_or_update(resource.change.actions)
    not valid_zones(resource.change.after)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2: '%s' `azurerm_kubernetes_cluster` must have configured `default_node_pool` to use at least 2 Availability Zones: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/ContainerService/managedClusters/#deploy-aks-cluster-across-availability-zones", [resource.address])
}