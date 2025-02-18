package checkov

import rego.v1


ANONYMOUS_PULL_SKUS := ["Standard", "Premium"]

valid_azurerm_container_registry_anonymous_pull_disabled(resource) if {
    not (
        resource.values.sku != null
        resource.values.sku == ANONYMOUS_PULL_SKUS[_]
        resource.values.anonymous_pull_enabled != null
        resource.values.anonymous_pull_enabled == true
    )
}

deny_acr_anonymous_pull_enabled contains reason if {
    resource := data.utils.resource(input, "azurerm_container_registry")[_]
    not valid_azurerm_container_registry_anonymous_pull_disabled(resource)

    reason := sprintf("checkov/CKV_AZURE_138: Ensures that ACR disables anonymous pulling of images. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/ACRAnonymousPullDisabled.py")
}
