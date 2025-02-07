package Azure_Proactive_Resiliency_Library_v2.azurerm_mysql_flexible_server

valid_geo_redundant_backup_enabled(resource) {
    resource.change.after.geo_redundant_backup_enabled == true
}

deny_mysql_flexible_server_high_availability_zone_redundant[reason] {
    tfplan := data.utils.tfplan(input)
    resource := tfplan.resource_changes[_]
    resource.mode == "managed"
    resource.type == "azurerm_mysql_flexible_server"
    data.utils.is_create_or_update(resource.change.actions)
    not valid_geo_redundant_backup_enabled(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2: '%s' `azurerm_mysql_flexible_server` must have 'geo_redundant_backup_enabled.mode' set to 'true': https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DBforMySQL/flexibleServers/#configure-geo-redundant-backup-storage", [resource.address])
}