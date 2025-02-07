package Azure_Proactive_Resiliency_Library_v2.azurerm_mysql_flexible_server

valid_high_availability_mode(resource) {
    resource.change.after.high_availability[_].mode == "ZoneRedundant"
}

deny_mysql_flexible_server_high_availability_mode_zone_redundant[reason] {
    tfplan := data.utils.tfplan(input)
    resource := tfplan.resource_changes[_]
    resource.mode == "managed"
    resource.type == "azurerm_mysql_flexible_server"
    data.utils.is_create_or_update(resource.change.actions)
    not valid_high_availability_mode(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2: '%s' `azurerm_mysql_flexible_server` must have 'high_availability.mode' set to 'ZoneRedundant': https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DBforMySQL/flexibleServers/#enable-ha-with-zone-redundancy", [resource.address])
}