package checkov

import rego.v1

valid_azurerm_app_service_identity_enabled(resource) if {
    resource.identity[_].type != null
}

deny_CKV_AZURE_71 contains reason if {
    resource := data.utils.resource(input, "azurerm_app_service")[_]

    not valid_azurerm_app_service_identity_enabled(resource)
    reason := sprintf("checkov/CKV_AZURE_71: Ensure that Managed identity provider is enabled for app services. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceIdentityProviderEnabled.py")
}

deny_CKV_AZURE_71 contains reason if {
    resource := data.utils.resource(input, "azurerm_linux_web_app")[_]

    not valid_azurerm_app_service_identity_enabled(resource)
    reason := sprintf("checkov/CKV_AZURE_71: Ensure that Managed identity provider is enabled for app services. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceIdentityProviderEnabled.py")
}

deny_CKV_AZURE_71 contains reason if {
    resource := data.utils.resource(input, "azurerm_windows_web_app")[_]

    not valid_azurerm_app_service_identity_enabled(resource)
    reason := sprintf("checkov/CKV_AZURE_71: Ensure that Managed identity provider is enabled for app services. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceIdentityProviderEnabled.py")
}
