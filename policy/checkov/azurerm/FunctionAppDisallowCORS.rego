package checkov

import rego.v1

valid_azurerm_function_app_cors(resource) if {
    not contains(resource.values.site_config[0].cors[0].allowed_origins, "*")
}

deny_CKV_AZURE_62 contains reason if {
    resource := data.utils.resource(input, "azurerm_function_app")[_]
    not valid_azurerm_function_app_cors(resource)

    reason := sprintf("checkov/CKV_AZURE_62: Ensure function apps are not accessible from all regions. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/FunctionAppDisallowCORS.py")
}
