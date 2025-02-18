package checkov

import rego.v1

valid_azurerm_function_app_enable_builtin_logging(resource) if {
    resource.values.enable_builtin_logging == true
}

deny_function_app_enable_logging contains reason if {
    resource := data.utils.resource(input, "azurerm_function_app")[_]

    not valid_azurerm_function_app_enable_builtin_logging(resource)

    reason := sprintf("checkov/CKV_AZURE_159: Ensure function app builtin logging is enabled. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/FunctionAppEnableLogging.py")
}

deny_function_app_slot_enable_logging contains reason if {
    resource := data.utils.resource(input, "azurerm_function_app_slot")[_]

    not valid_azurerm_function_app_enable_builtin_logging(resource)

    reason := sprintf("checkov/CKV_AZURE_159: Ensure function app builtin logging is enabled. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/FunctionAppEnableLogging.py")
}
