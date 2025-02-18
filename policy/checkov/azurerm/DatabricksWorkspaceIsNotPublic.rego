package checkov

import rego.v1

valid_azurerm_databricks_workspace_is_not_public(resource) if {
    resource.values.public_network_access_enabled != true
}

deny_databricks_workspace_is_not_public contains reason if {
    resource := data.utils.resource(input, "azurerm_databricks_workspace")[_]
    not valid_azurerm_databricks_workspace_is_not_public(resource)

    reason := sprintf("checkov/CKV_AZURE_158: Ensure that databricks workspace has not public %s", [resource.address])
    reason := reason + " https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/DatabricksWorkspaceIsNotPublic.py"
}
