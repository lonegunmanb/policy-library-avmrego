package Azure_Proactive_Resiliency_Library_v2.Microsoft_Network_applicationGateways

valid_zones(after) {
    after.body.zones
    count(after.body.zones) >= 2
}

deny[reason] {
    tfplan := data.utils.tfplan(input)
    resource := tfplan.resource_changes[_]
    resource.mode == "managed"
    resource.type == "azapi_resource"
    regex.match(`^Microsoft.Network/applicationGateways@`, resource.change.after.type)
    data.utils.is_create_or_update(resource.change.actions)
    not valid_zones(resource.change.after)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2: '%s' `azapi_resource` must have must have configured to use at least 2 Availability Zones: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/applicationGateways/#deploy-application-gateway-in-a-zone-redundant-configuration", [resource.address])
}