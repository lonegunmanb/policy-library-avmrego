package Azure_Proactive_Resiliency_Library_v2.Microsoft_ContainerService_managedClusters

import rego.v1

valid_zones(resource) if {
    pool := resource.values.body.properties.agentPoolProfiles[_]
    count(pool.availabilityZones) >= 2
}

deny_configure_aks_default_node_pool_zones contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.ContainerService/managedClusters")
    not valid_zones(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2: '%s' `azapi_resource` must have configured `agentPoolProfiles.availabilityZones` to use at least 2 Availability Zones: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/ContainerService/managedClusters/#deploy-aks-cluster-across-availability-zones", [resource.address])
}