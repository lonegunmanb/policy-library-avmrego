package checkov

import rego.v1

valid_azurerm_storage_account_queue_logging(resource) if {
    resource.values.account_kind != "Storage"
    resource.values.account_kind != "StorageV2"
}

valid_azurerm_storage_account_queue_logging(resource) if {
    queue_properties := resource.values.queue_properties[_]
    logging := queue_properties.logging[_]
    logging.delete == true
    logging.write == true
    logging.read == true
}

deny_CKV_AZURE_33 contains reason if {
    resource := data.utils.resource(input, "azurerm_storage_account")[_]
    not valid_azurerm_storage_account_queue_logging(resource)

    reason := sprintf("checkov/CKV_AZURE_33: Ensure Storage logging is enabled for Queue service for read, write and delete requests. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageAccountLoggingQueueServiceEnabled.py")
}
