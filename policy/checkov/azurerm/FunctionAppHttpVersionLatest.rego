package checkov

import rego.v1

valid_azurerm_function_app_http2_enabled(resource) if {
    resource.values.site_config[0].http2_enabled == true
}

deny_CKV_AZURE_67 contains reason if {
    resource := data.utils.resource(input, "azurerm_function_app")[_]

    not valid_azurerm_function_app_http2_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_67: Ensure that 'HTTP Version' is the latest, if used to run the Function app. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/FunctionAppHttpVersionLatest.py")
}

deny_CKV_AZURE_67 contains reason if {
    resource := data.utils.resource(input, "azurerm_function_app_slot")[_]

    not valid_azurerm_function_app_http2_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_67: Ensure that 'HTTP Version' is the latest, if used to run the Function app. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/FunctionAppHttpVersionLatest.py")
}