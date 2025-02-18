package checkov

import rego.v1

valid_azurerm_function_app_min_tls_version(resource) if {
    resource.values.site_config[0].min_tls_version >= 1.2
}

deny_function_app_min_tls_version contains reason if {
    resource := data.utils.resource(input, "azurerm_function_app")[_]
    not valid_azurerm_function_app_min_tls_version(resource)

    reason := sprintf("checkov/CKV_AZURE_145: Ensure Function app is using the latest version of TLS encryption. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/FunctionAppMinTLSVersion.py")
}