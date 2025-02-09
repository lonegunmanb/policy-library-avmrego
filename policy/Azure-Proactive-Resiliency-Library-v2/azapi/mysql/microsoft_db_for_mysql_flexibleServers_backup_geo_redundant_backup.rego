package Azure_Proactive_Resiliency_Library_v2.Microsoft_DBforMySQL_flexibleServers

import rego.v1

valid_geo_redundant_backup_enabled(resource) if {
    resource.values.body.properties.backup.geoRedundantBackup == "Enabled"
}

deny_mysql_flexible_server_geo_redundant_backup_enabled contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.DBforMySQL/flexibleServers")
    not valid_geo_redundant_backup_enabled(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2: '%s' `azapi_resource` must have 'backup.geoRedundantBackup' set to '\"Enabled\"': https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DBforMySQL/flexibleServers/#configure-geo-redundant-backup-storage", [resource.address])
}