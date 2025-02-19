package checkov

import rego.v1

valid_azurerm_app_service_slot_min_tls(resource) if {
    resource.values.site_config[0].min_tls_version[0] == "1.2"
}

deny_CKV_AZURE_154 contains reason if {
    resource := data.utils.resource(input, "azurerm_app_service_slot")[_]
    not valid_azurerm_app_service_slot_min_tls(resource)

    reason := sprintf("checkov/CKV_AZURE_154: Ensure the App service slot is using the latest version of TLS encryption. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceSlotMinTLS.py")
}
