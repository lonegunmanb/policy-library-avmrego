package checkov

import rego.v1

valid_azurerm_spring_cloud_api_portal_https_only(resource) if {
    resource.values.https_only_enabled == true
}

deny_CKV_AZURE_161 contains reason if {
    resource := data.utils.resource(input, "azurerm_spring_cloud_api_portal")[_]
    not valid_azurerm_spring_cloud_api_portal_https_only(resource)

    reason := sprintf("checkov/CKV_AZURE_161: Ensure Spring Cloud API Portal is enabled on for HTTPS. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SpringCloudAPIPortalHTTPSOnly.py", [resource.address])
}
