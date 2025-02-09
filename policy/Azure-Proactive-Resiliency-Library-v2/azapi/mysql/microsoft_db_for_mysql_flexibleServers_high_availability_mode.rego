package Azure_Proactive_Resiliency_Library_v2.Microsoft_DBforMySQL_flexibleServers

import rego.v1

valid_high_availability_mode(resource) if {
    resource.values.body.properties.highAvailability.mode == "ZoneRedundant"
}

deny_mysql_flexible_server_high_availability_zone_redundant contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.DBforMySQL/flexibleServers")
    not valid_high_availability_mode(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2: '%s' `azapi_resource` must have 'highAvailability.mode' set to 'ZoneRedundant': https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DBforMySQL/flexibleServers/#enable-ha-with-zone-redundancy", [resource.address])
}