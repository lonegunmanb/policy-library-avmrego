package Azure_Proactive_Resiliency_Library_v2.postgresql_flexible_server_high_availability_mode_zone_redundant

import rego.v1

valid_azurerm_high_availability_mode(resource) if {
    resource.values.high_availability[_].mode == "ZoneRedundant"
}

deny_postgresql_flexible_server_high_availability_mode_zone_redundant contains reason if {
    resource := data.utils.resource(input, "azurerm_postgresql_flexible_server")[_]
    not valid_azurerm_high_availability_mode(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2: '%s' `azurerm_postgresql_flexible_server` must have 'high_availability.mode' set to 'ZoneRedundant': https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DBforPostgreSQL/flexibleServers/#enable-ha-with-zone-redundancy", [resource.address])
}