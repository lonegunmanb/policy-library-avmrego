package checkov

import rego.v1

valid_azurerm_app_service_detailed_error_messages_enabled(resource) if {
    resource.values.logs[0].detailed_error_messages_enabled == true
}

valid_azurerm_linux_web_app_detailed_error_messages(resource) if {
    resource.values.logs[0].detailed_error_messages == true
}

valid_azurerm_windows_web_app_detailed_error_messages(resource) if {
    resource.values.logs[0].detailed_error_messages == true
}

deny_CKV_AZURE_65 contains reason if {
    resource := data.utils.resource(input, "azurerm_app_service")[_]
    not valid_azurerm_app_service_detailed_error_messages_enabled(resource)
    reason := sprintf("checkov/CKV_AZURE_65: Ensure that App service enables detailed error messages for azurerm_app_service %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceDetailedErrorMessagesEnabled.py", [resource.address])
}

deny_CKV_AZURE_65 contains reason if {
    resource := data.utils.resource(input, "azurerm_linux_web_app")[_]
    not valid_azurerm_linux_web_app_detailed_error_messages(resource)
    reason := sprintf("checkov/CKV_AZURE_65: Ensure that App service enables detailed error messages for azurerm_linux_web_app %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceDetailedErrorMessagesEnabled.py", [resource.address])
}

deny_CKV_AZURE_65 contains reason if {
    resource := data.utils.resource(input, "azurerm_windows_web_app")[_]
    not valid_azurerm_windows_web_app_detailed_error_messages(resource)
    reason := sprintf("checkov/CKV_AZURE_65: Ensure that App service enables detailed error messages for azurerm_windows_web_app %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceDetailedErrorMessagesEnabled.py", [resource.address])
}
