package Azure_Proactive_Resiliency_Library_v2.azurerm_application_gateway

import rego.v1

valid_zones(resource) if {
    data.utils.exists(resource.values.zones)
    count(resource.values.zones) >= 2
}

deny_deploy_application_gateway_in_a_zone_redundant_configuration contains reason if {
    resource := data.utils.resource(input, "azurerm_application_gateway")[_]
    not valid_zones(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2: '%s' `azurerm_application_gateway` must have configured to use at least 2 Availability Zones: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/applicationGateways/#deploy-application-gateway-in-a-zone-redundant-configuration", [resource.address])
}