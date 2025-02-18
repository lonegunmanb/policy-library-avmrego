package checkov

import rego.v1

valid_azurerm_container_registry_public_network_access_disabled(resource) if {
    resource.values.public_network_access_enabled == false
}

deny_acr_public_network_access_disabled contains reason if {
    resource := data.utils.resource(input, "azurerm_container_registry")[_]
    not valid_azurerm_container_registry_public_network_access_disabled(resource)

    reason := sprintf("checkov/CKV_AZURE_139: Ensure ACR set to disable public networking %s", [resource.address])
    reason := reason + " https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/ACRPublicNetworkAccessDisabled.py"
}
