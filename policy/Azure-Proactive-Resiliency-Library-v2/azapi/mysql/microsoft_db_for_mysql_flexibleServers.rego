package Azure_Proactive_Resiliency_Library_v2.Microsoft_DBforMySQL_flexibleServers

valid_high_availability_mode(after) {
    pool := after.body.properties.highAvailability.mode == "ZoneRedundant"
}

deny_mysql_flexible_server_high_availability_zone_redundant[reason] {
    tfplan := data.utils.tfplan(input)
    resource := tfplan.resource_changes[_]
    resource.mode == "managed"
    resource.type == "azapi_resource"
    data.utils.is_azure_type(resource.change.after, "Microsoft.DBforMySQL/flexibleServers")
    data.utils.is_create_or_update(resource.change.actions)
    not valid_high_availability_mode(resource.change.after)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2: '%s' `azapi_resource` must have 'highAvailability.mode' set to 'ZoneRedundant': https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DBforMySQL/flexibleServers/#enable-ha-with-zone-redundancy", [resource.address])
}