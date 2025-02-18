package checkov

import rego.v1

valid_azurerm_app_service_identity_enabled(resource) if {
    resource.identity != null
    count(resource.identity) > 0
    resource.identity[0].type != null
}

deny_app_service_identity_enabled contains reason if {
    resource := input.resource
    resource.type == "azurerm_app_service" or resource.type == "azurerm_linux_web_app" or resource.type == "azurerm_windows_web_app"
    not valid_azurerm_app_service_identity_enabled(resource.properties)

    reason := sprintf("checkov/CKV_AZURE_71: Ensure that Managed identity provider is enabled for app services. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceIdentityProviderEnabled.py")
}
