package checkov

import rego.v1

valid_azurerm_machine_learning_workspace_public_access_disabled(resource) if {
    resource.values.public_network_access_enabled == false
}

deny_CKV_AZURE_144 contains reason if {
    resource := data.utils.resource(input, "azurerm_machine_learning_workspace")[_]
    not valid_azurerm_machine_learning_workspace_public_access_disabled(resource)

    reason := sprintf("checkov/CKV_AZURE_144: Ensure that Public Access is disabled for Machine Learning Workspace '%s': https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/MLPublicAccess.py", [resource.address])
}
