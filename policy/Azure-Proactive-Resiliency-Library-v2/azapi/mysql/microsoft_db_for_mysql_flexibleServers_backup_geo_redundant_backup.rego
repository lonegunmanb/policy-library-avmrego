package Azure_Proactive_Resiliency_Library_v2.Microsoft_DBforMySQL_flexibleServers

import rego.v1

valid_geo_redundant_backup_enabled(after) if {
    after.body.properties.backup.geoRedundantBackup == "Enabled"
}

deny_mysql_flexible_server_geo_redundant_backup_enabled contains reason if {
    tfplan := data.utils.tfplan(input)
    resource := tfplan.resource_changes[_]
    resource.mode == "managed"
    resource.type == "azapi_resource"
    data.utils.is_azure_type(resource.change.after, "Microsoft.DBforMySQL/flexibleServers")
    data.utils.is_create_or_update(resource.change.actions)
    not valid_geo_redundant_backup_enabled(resource.change.after)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2: '%s' `azapi_resource` must have 'backup.geoRedundantBackup' set to '\"Enabled\"': https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DBforMySQL/flexibleServers/#configure-geo-redundant-backup-storage", [resource.address])
}