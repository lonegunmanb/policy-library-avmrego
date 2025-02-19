package checkov

import rego.v1

valid_azurerm_app_service_remote_debugging_disabled(resource) if {
    resource.values.remote_debugging_enabled == false
}

deny_CKV_AZURE_72 contains reason if {
    resource := data.utils.resource(input, "azurerm_app_service")[_]
    not valid_azurerm_app_service_remote_debugging_disabled(resource)

    reason := sprintf("checkov/CKV_AZURE_72: Ensure that remote debugging is not enabled for app services. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/RemoteDebggingNotEnabled.py", [])
}
