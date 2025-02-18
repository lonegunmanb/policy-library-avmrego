package checkov

import rego.v1

valid_azurerm_app_service_https_only(resource) if {
    resource.values.https_only == true
}

deny_app_service_https_only contains reason if {
    resource := data.utils.resource(input, "azurerm_app_service")[_]

    not valid_azurerm_app_service_https_only(resource)

    reason := sprintf("checkov/CKV_AZURE_14: Ensure web app redirects all HTTP traffic to HTTPS in Azure App Service %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceHTTPSOnly.py", [resource.address])
}

deny_linux_web_app_https_only contains reason if {
    resource := data.utils.resource(input, "azurerm_linux_web_app")[_]

    not valid_azurerm_app_service_https_only(resource)

    reason := sprintf("checkov/CKV_AZURE_14: Ensure web app redirects all HTTP traffic to HTTPS in Azure App Service %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceHTTPSOnly.py", [resource.address])
}

deny_windows_web_app_https_only contains reason if {
    resource := data.utils.resource(input, "azurerm_windows_web_app")[_]

    not valid_azurerm_app_service_https_only(resource)

    reason := sprintf("checkov/CKV_AZURE_14: Ensure web app redirects all HTTP traffic to HTTPS in Azure App Service %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceHTTPSOnly.py", [resource.address])
}
