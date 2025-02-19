package checkov

import rego.v1

valid_azurerm_app_service_cors_allowed_origins(resource) if {
    not (resource.values.site_config[0].cors[0].allowed_origins == ["*"])
}

deny_CKV_AZURE_57 contains reason if {
    resource := data.utils.resource(input, "azurerm_app_service")[_]

    not valid_azurerm_app_service_cors_allowed_origins(resource)

    reason := sprintf("checkov/CKV_AZURE_57: Ensure that CORS disallows every resource to access app services. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceDisallowCORS.py")
}

deny_CKV_AZURE_57 contains reason if {
    resource := data.utils.resource(input, "azurerm_linux_web_app")[_]

    not valid_azurerm_app_service_cors_allowed_origins(resource)

    reason := sprintf("checkov/CKV_AZURE_57: Ensure that CORS disallows every resource to access app services. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceDisallowCORS.py")
}

deny_CKV_AZURE_57 contains reason if {
    resource := data.utils.resource(input, "azurerm_windows_web_app")[_]

    not valid_azurerm_app_service_cors_allowed_origins(resource)

    reason := sprintf("checkov/CKV_AZURE_57: Ensure that CORS disallows every resource to access app services. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceDisallowCORS.py")
}
