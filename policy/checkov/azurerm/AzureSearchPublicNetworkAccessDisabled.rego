package checkov

import rego.v1

valid_azurerm_search_service_public_network_access_disabled(resource) if {
    resource.values.public_network_access_enabled == false
}

deny_search_service_public_network_access_enabled contains reason if {
    resource := data.utils.resource(input, "azurerm_search_service")[_]
    not valid_azurerm_search_service_public_network_access_disabled(resource)

    reason := sprintf("checkov/CKV_AZURE_124: Ensure that Azure Cognitive Search disables public network access. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureSearchPublicNetworkAccessDisabled.py", [])
}
