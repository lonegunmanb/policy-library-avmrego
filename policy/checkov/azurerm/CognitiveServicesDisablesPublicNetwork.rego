package checkov

import rego.v1

valid_azurerm_cognitive_account_public_network_disabled(resource) if {
    resource.values.public_network_access_enabled == false
}

deny_CKV_AZURE_134 contains reason if {
    resource := data.utils.resource(input, "azurerm_cognitive_account")[_]
    not valid_azurerm_cognitive_account_public_network_disabled(resource)

    reason := sprintf("checkov/CKV_AZURE_134: Ensure that Cognitive Services accounts disable public network access '%s'. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/CognitiveServicesDisablesPublicNetwork.py", [resource.address])
}
