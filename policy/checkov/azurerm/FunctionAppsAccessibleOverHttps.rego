package checkov

import rego.v1

valid_azurerm_function_app_https_only(resource) if {
    resource.values.https_only == true
}

deny_CKV_AZURE_70 contains reason if {
    resource := data.utils.resource(input, "azurerm_function_app")[_]
    not valid_azurerm_function_app_https_only(resource)

    reason := sprintf("checkov/CKV_AZURE_70: Ensure that Function apps is only accessible over HTTPS %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/FunctionAppsAccessibleOverHttps.py", [resource.address])
}
