package checkov

import rego.v1

valid_azurerm_synapse_workspace_managed_network_enabled(resource) if {
    resource.values.managed_virtual_network_enabled == true
}

deny_CKV_AZURE_58 contains reason if {
    resource := data.utils.resource(input, "azurerm_synapse_workspace")[_]
    not valid_azurerm_synapse_workspace_managed_network_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_58: Ensure that Azure Synapse workspaces enables managed virtual networks. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SynapseWorkspaceEnablesManagedVirtualNetworks.py")
}
