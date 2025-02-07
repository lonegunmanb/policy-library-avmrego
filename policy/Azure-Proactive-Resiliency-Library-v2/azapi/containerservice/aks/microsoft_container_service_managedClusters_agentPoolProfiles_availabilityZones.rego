package Azure_Proactive_Resiliency_Library_v2.Microsoft_ContainerService_managedClusters

import rego.v1

valid_zones(after) if {
    pool := after.body.properties.agentPoolProfiles[_]
    count(pool.availabilityZones) >= 2
}

deny_configure_aks_default_node_pool_zones contains reason if {
    tfplan := data.utils.tfplan(input)
    resource := tfplan.resource_changes[_]
    resource.mode == "managed"
    resource.type == "azapi_resource"
    data.utils.is_azure_type(resource.change.after, "Microsoft.ContainerService/managedClusters")
    data.utils.is_create_or_update(resource.change.actions)
    not valid_zones(resource.change.after)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2: '%s' `azapi_resource` must have configured `agentPoolProfiles.availabilityZones` to use at least 2 Availability Zones: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/ContainerService/managedClusters/#deploy-aks-cluster-across-availability-zones", [resource.address])
}