package checkov

import rego.v1

valid_azurerm_app_service_http_logging_enabled(resource) if {
    resource.values.logs[0].http_logs != null
}

deny_app_service_http_logging_enabled contains reason if {
    resource := data.utils.resource(input, ["azurerm_app_service", "azurerm_linux_web_app", "azurerm_windows_web_app"])[_]
    not valid_azurerm_app_service_http_logging_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_63: Ensure that App service enables HTTP logging %s", [resource.address])

    reason := reason + ". https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceHttpLoggingEnabled.py"
}
