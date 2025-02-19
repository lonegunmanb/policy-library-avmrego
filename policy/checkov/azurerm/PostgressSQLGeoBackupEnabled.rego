package checkov

import rego.v1

valid_azurerm_postgresql_server_geo_backup_enabled(resource) if {
    resource.values.geo_redundant_backup_enabled == true
}

deny_CKV_AZURE_102 contains reason if {
    resource := data.utils.resource(input, "azurerm_postgresql_server")[_]
    not valid_azurerm_postgresql_server_geo_backup_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_102: Ensure that PostgreSQL server enables geo-redundant backups. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/PostgressSQLGeoBackupEnabled.py")
}
