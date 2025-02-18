package checkov

import rego.v1

valid_azurerm_function_app_accessible_over_https(resource) if {
    resource.values.https_only == true
}

deny_function_app_accessible_over_https contains reason if {
    resource := data.utils.resource(input, "azurerm_function_app")[_]
    not valid_azurerm_function_app_accessible_over_https(resource)

    reason := sprintf("checkov/CKV_AZURE_70: Ensure that Function apps is only accessible over HTTPS. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/FunctionAppsAccessibleOverHttps.py", [])
}
