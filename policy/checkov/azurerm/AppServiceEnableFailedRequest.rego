package checkov

import rego.v1

valid_azurerm_app_service_failed_request_tracing(resource) if {
    resource.values.logs[0].failed_request_tracing_enabled == true
}

valid_azurerm_linux_web_app_failed_request_tracing(resource) if {
    resource.values.logs[0].failed_request_tracing == true
}

valid_azurerm_windows_web_app_failed_request_tracing(resource) if {
    resource.values.logs[0].failed_request_tracing == true
}

deny_CKV_AZURE_66 contains reason if {
    resource := data.utils.resource(input, "azurerm_linux_web_app")[_]
    not valid_azurerm_linux_web_app_failed_request_tracing(resource)
    reason := sprintf("checkov/CKV_AZURE_66: Ensure that App service enables failed request tracing for azurerm_linux_web_app '%s' https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceEnableFailedRequest.py", [resource.address])
}

deny_CKV_AZURE_66 contains reason if {
    resource := data.utils.resource(input, "azurerm_windows_web_app")[_]
    not valid_azurerm_windows_web_app_failed_request_tracing(resource)
    reason := sprintf("checkov/CKV_AZURE_66: Ensure that App service enables failed request tracing for azurerm_windows_web_app '%s' https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceEnableFailedRequest.py", [resource.address])
}

deny_CKV_AZURE_66 contains reason if {
    resource := data.utils.resource(input, "azurerm_app_service")[_]
    not valid_azurerm_app_service_failed_request_tracing(resource)
    reason := sprintf("checkov/CKV_AZURE_66: Ensure that App service enables failed request tracing for azurerm_app_service '%s' https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceEnableFailedRequest.py", [resource.address])
}
