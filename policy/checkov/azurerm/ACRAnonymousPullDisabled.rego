package checkov

import rego.v1

valid_azurerm_container_registry_anonymous_pull_disabled(resource) if {
    not (resource.values.sku == "Standard" or resource.values.sku == "Premium")
}

valid_azurerm_container_registry_anonymous_pull_disabled(resource) if {
    not resource.values.anonymous_pull_enabled == true
}

deny_CKV_AZURE_138 contains reason if {
    resource := data.utils.resource(input, "azurerm_container_registry")[_]
    not valid_azurerm_container_registry_anonymous_pull_disabled(resource)
    reason := sprintf("checkov/CKV_AZURE_138: Ensures that ACR disables anonymous pulling of images. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/ACRAnonymousPullDisabled.py")
}
