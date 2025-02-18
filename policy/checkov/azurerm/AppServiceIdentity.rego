package checkov

import rego.v1

valid_azurerm_app_service_has_identity(resource) if {
    resource.identity != null
}

deny_app_service_must_have_identity contains reason if {
    resource := data.utils.resource(input, ["azurerm_app_service", "azurerm_linux_web_app", "azurerm_windows_web_app"])[_]
    not valid_azurerm_app_service_has_identity(resource)

    reason := sprintf("checkov/CKV_AZURE_16: Ensure that Register with Azure Active Directory is enabled on App Service %s. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceIdentity.py", [resource.address])
}
