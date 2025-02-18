package checkov

import rego.v1

valid_azurerm_app_service_slot_https_only(resource) if {
    resource.values.https_only == true
}

deny_app_service_slot_https_only contains reason if {
    resource := data.utils.resource(input, "azurerm_app_service_slot")[_]
    not valid_azurerm_app_service_slot_https_only(resource)

    reason := sprintf("checkov/CKV_AZURE_153: Ensure web app redirects all HTTP traffic to HTTPS in Azure App Service Slot '%s'. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceSlotHTTPSOnly.py", [resource.address])
}
