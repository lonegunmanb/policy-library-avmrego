package checkov

import rego.v1

valid_azurerm_synapse_workspace_data_exfiltration(resource) if {
    resource.values.data_exfiltration_protection_enabled == true
}

deny_CKV_AZURE_157 contains reason if {
    resource := data.utils.resource(input, "azurerm_synapse_workspace")[_]
    not valid_azurerm_synapse_workspace_data_exfiltration(resource)

    reason := sprintf("checkov/CKV_AZURE_157: Ensure that Synapse workspace has data_exfiltration_protection_enabled for %s. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SynapseWorkspaceEnablesDataExfilProtection.py", [resource.address])
}
