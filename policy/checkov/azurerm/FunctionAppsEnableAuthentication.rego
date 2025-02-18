package checkov

import rego.v1

valid_azurerm_function_app_enable_authentication(resource) if {
    resource.values.auth_settings[0].enabled == true
}

deny_function_app_enable_authentication contains reason if {
    resource := data.utils.resource(input, "azurerm_function_app")[_]
    not valid_azurerm_function_app_enable_authentication(resource)

    reason := sprintf("checkov/CKV_AZURE_56: Ensure that function apps enables Authentication. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/FunctionAppsEnableAuthentication.py")
}
