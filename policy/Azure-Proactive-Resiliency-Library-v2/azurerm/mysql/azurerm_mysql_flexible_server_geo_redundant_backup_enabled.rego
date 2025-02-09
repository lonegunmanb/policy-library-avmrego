package Azure_Proactive_Resiliency_Library_v2.azurerm_mysql_flexible_server

import rego.v1

valid_geo_redundant_backup_enabled(resource) if {
    resource.values.geo_redundant_backup_enabled == true
}

deny_mysql_flexible_server_geo_redundant_backup_enabled contains reason if {
    resource := data.utils.resource(input, "azurerm_mysql_flexible_server")[_]
    not valid_geo_redundant_backup_enabled(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2: '%s' `azurerm_mysql_flexible_server` must have 'geo_redundant_backup_enabled.mode' set to 'true': https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DBforMySQL/flexibleServers/#configure-geo-redundant-backup-storage", [resource.address])
}