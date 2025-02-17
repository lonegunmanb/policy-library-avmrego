package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azapi_deploy_application_gateway_in_a_zone_redundant_configuration(resource) if {
    resource.values.body.zones == resource.values.body.zones
    count(resource.values.body.zones) >= 2
}

deny_deploy_application_gateway_in_a_zone_redundant_configuration contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.Network/applicationGateways")
    not valid_azapi_deploy_application_gateway_in_a_zone_redundant_configuration(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2: '%s' `azapi_resource` must have must have configured to use at least 2 Availability Zones: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/applicationGateways/#deploy-application-gateway-in-a-zone-redundant-configuration", [resource.address])
}