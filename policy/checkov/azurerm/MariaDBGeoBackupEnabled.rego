package checkov

import rego.v1

valid_azurerm_mariadb_server_geo_backup_enabled(resource) if {
    resource.values.geo_redundant_backup_enabled == true
}

deny_CKV_AZURE_129 contains reason if {
    resource := data.utils.resource(input, "azurerm_mariadb_server")[_]
    not valid_azurerm_mariadb_server_geo_backup_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_129: Ensure that MariaDB server enables geo-redundant backups. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/MariaDBGeoBackupEnabled.py")
}
