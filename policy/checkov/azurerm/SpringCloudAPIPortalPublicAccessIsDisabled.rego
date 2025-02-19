package checkov

import rego.v1

valid_azurerm_spring_cloud_api_portal_public_access_is_disabled(resource) if {
    resource.values.public_network_access_enabled == false
}

deny_CKV_AZURE_162 contains reason if {
    resource := data.utils.resource(input, "azurerm_spring_cloud_api_portal")[_]
    not valid_azurerm_spring_cloud_api_portal_public_access_is_disabled(resource)

    reason := sprintf("checkov/CKV_AZURE_162: Ensure Spring Cloud API Portal Public Access Is Disabled '%s' `azurerm_spring_cloud_api_portal` must have 'public_network_access_enabled' set to 'false': https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SpringCloudAPIPortalPublicAccessIsDisabled.py", [resource.address])
}