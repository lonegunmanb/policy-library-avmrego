package checkov

import rego.v1

valid_azurerm_app_service_authentication(resource) if {
    resource.values.auth_settings[0].enabled == true
}

deny_CKV_AZURE_13 contains reason if {
    resource := data.utils.resource(input, ["azurerm_app_service", "azurerm_linux_web_app", "azurerm_windows_web_app"])[_]
    not valid_azurerm_app_service_authentication(resource)

    reason := sprintf("checkov/CKV_AZURE_13: Ensure App Service Authentication is set on Azure App Service for %s. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceAuthentication.py", [resource.address])
}
