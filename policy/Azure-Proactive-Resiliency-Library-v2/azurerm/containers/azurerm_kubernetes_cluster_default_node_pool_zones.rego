package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azurerm_configure_aks_default_node_pool_zones(resource) if {
    pool := resource.values.default_node_pool[_]
    count(pool.zones) >= 2
}

deny_configure_aks_default_node_pool_zones contains reason if {
    resource := data.utils.resource(input, "azurerm_kubernetes_cluster")[_]
    not valid_azurerm_configure_aks_default_node_pool_zones(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/configure_aks_default_node_pool_zones: '%s' `azurerm_kubernetes_cluster` must have configured `default_node_pool` to use at least 2 Availability Zones: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/ContainerService/managedClusters/#deploy-aks-cluster-across-availability-zones", [resource.address])
}