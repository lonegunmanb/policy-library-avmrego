package Azure_Proactive_Resiliency_Library_v2.azurerm_postgresql_flexible_server

import rego.v1

valid_high_availability_mode(resource) if {
    resource.change.after.high_availability[_].mode == "ZoneRedundant"
}

deny_postgresql_flexible_server_high_availability_mode_zone_redundant contains reason if {
    tfplan := data.utils.tfplan(input)
    resource := tfplan.resource_changes[_]
    resource.mode == "managed"
    resource.type == "azurerm_postgresql_flexible_server"
    data.utils.is_create_or_update(resource.change.actions)
    not valid_high_availability_mode(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2: '%s' `azurerm_postgresql_flexible_server` must have 'high_availability.mode' set to 'ZoneRedundant': https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DBforPostgreSQL/flexibleServers/#enable-ha-with-zone-redundancy", [resource.address])
}