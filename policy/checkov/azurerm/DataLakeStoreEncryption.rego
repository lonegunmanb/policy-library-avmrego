package checkov

import rego.v1

valid_azurerm_data_lake_store_encryption_enabled(resource) if {
    resource.values.encryption_state == "Enabled"
}

deny_CKV_AZURE_105 contains reason if {
    resource := data.utils.resource(input, "azurerm_data_lake_store")[_]
    not valid_azurerm_data_lake_store_encryption_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_105: Ensure that Data Lake Store accounts enables encryption %s", [resource.address])
}
