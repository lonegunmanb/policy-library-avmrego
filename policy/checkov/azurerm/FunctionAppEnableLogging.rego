package checkov

import rego.v1

valid_azurerm_function_app_enable_builtin_logging(resource) if {
    resource.values.enable_builtin_logging == true
}

deny_CKV_AZURE_159 contains reason if {
    resource := data.utils.resource(input, "azurerm_function_app")[_]

    not valid_azurerm_function_app_enable_builtin_logging(resource)

    reason := sprintf("checkov/CKV_AZURE_159: Ensure function app builtin logging is enabled %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/FunctionAppEnableLogging.py", [resource.address])
}

deny_CKV_AZURE_159 contains reason if {
    resource := data.utils.resource(input, "azurerm_function_app_slot")[_]

    not valid_azurerm_function_app_enable_builtin_logging(resource)

    reason := sprintf("checkov/CKV_AZURE_159: Ensure function app builtin logging is enabled %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/FunctionAppEnableLogging.py", [resource.address])
}
