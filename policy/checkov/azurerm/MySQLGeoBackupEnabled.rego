package checkov

import rego.v1

valid_azurerm_mysql_geo_backup_enabled(resource) if {
    resource.values.geo_redundant_backup_enabled == true
}

deny_mysql_geo_backup_enabled contains reason if {
    resource := data.utils.resource(input, "azurerm_mysql_server")[_]
    not valid_azurerm_mysql_geo_backup_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_94: Ensure that My SQL server enables geo-redundant backups '%s' `azurerm_mysql_server` must have 'geo_redundant_backup_enabled' set to true: https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/MySQLGeoBackupEnabled.py", [resource.address])
}
