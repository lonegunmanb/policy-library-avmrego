package checkov

import rego.v1

valid_azurerm_app_service_min_tls_version(resource) if {
    resource.values.site_config[0].min_tls_version[0] == "1.2"
}

valid_azurerm_linux_web_app_min_tls_version(resource) if {
    resource.values.site_config[0].minimum_tls_version[0] == "1.2"
}

valid_azurerm_windows_web_app_min_tls_version(resource) if {
    resource.values.site_config[0].minimum_tls_version[0] == "1.2"
}

deny_CKV_AZURE_15 contains reason if {
    resource := data.utils.resource(input, "azurerm_app_service")[_]
    not valid_azurerm_app_service_min_tls_version(resource)
    reason := sprintf("checkov/CKV_AZURE_15: Ensure web app is using the latest version of TLS encryption. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceMinTLSVersion.py")
}

deny_CKV_AZURE_15 contains reason if {
    resource := data.utils.resource(input, "azurerm_linux_web_app")[_]
    not valid_azurerm_linux_web_app_min_tls_version(resource)
    reason := sprintf("checkov/CKV_AZURE_15: Ensure web app is using the latest version of TLS encryption. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceMinTLSVersion.py")
}

deny_CKV_AZURE_15 contains reason if {
    resource := data.utils.resource(input, "azurerm_windows_web_app")[_]
    not valid_azurerm_windows_web_app_min_tls_version(resource)
    reason := sprintf("checkov/CKV_AZURE_15: Ensure web app is using the latest version of TLS encryption. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceMinTLSVersion.py")
}
