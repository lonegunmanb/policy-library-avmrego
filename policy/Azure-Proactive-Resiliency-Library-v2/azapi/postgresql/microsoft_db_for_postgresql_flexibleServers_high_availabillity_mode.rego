package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azapi_postgres_flexible_server_high_availability_zone_redundant(resource) if {
    resource.values.body.properties.highAvailability.mode == "ZoneRedundant"
}

deny_postgresql_flexible_server_high_availability_zone_redundant contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.DBforPostgreSQL/flexibleServers")
    not valid_azapi_postgres_flexible_server_high_availability_zone_redundant(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/postgresql_flexible_server_high_availability_zone_redundant: '%s' `azapi_resource` must have 'highAvailability.mode' set to 'ZoneRedundant': https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DBforPostgreSQL/flexibleServers/#enable-ha-with-zone-redundancy", [resource.address])
}