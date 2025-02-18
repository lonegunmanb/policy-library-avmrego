package checkov

import rego.v1

valid_azurerm_app_service_http2_enabled(resource) if {
    resource.values.site_config[0].http2_enabled == true
}

deny_app_service_http2_enabled contains reason if {
    resource := data.utils.resource(input, "azurerm_app_service")[_]
    not valid_azurerm_app_service_http2_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_18: Ensure that 'HTTP Version' is the latest if used to run the web app. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceHttps20Enabled.py")
}

deny_linux_web_app_http2_enabled contains reason if {
    resource := data.utils.resource(input, "azurerm_linux_web_app")[_]
    not valid_azurerm_app_service_http2_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_18: Ensure that 'HTTP Version' is the latest if used to run the web app. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceHttps20Enabled.py")
}

deny_windows_web_app_http2_enabled contains reason if {
    resource := data.utils.resource(input, "azurerm_windows_web_app")[_]
    not valid_azurerm_app_service_http2_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_18: Ensure that 'HTTP Version' is the latest if used to run the web app. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceHttps20Enabled.py")
}
