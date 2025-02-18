package checkov

import rego.v1

valid_azurerm_app_service_slot_debug_disabled(resource) if {
    resource.values.site_config[0].remote_debugging_enabled[0] == false
}

deny_app_service_slot_debug_enabled contains reason if {
    resource := data.utils.resource(input, "azurerm_app_service_slot")[_]
    not valid_azurerm_app_service_slot_debug_disabled(resource)

    reason := sprintf("checkov/CKV_AZURE_155: Ensure debugging is disabled for the App service slot '%s'. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceSlotDebugDisabled.py", [resource.address])
}
