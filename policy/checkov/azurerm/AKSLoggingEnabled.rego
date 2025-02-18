package checkov

import rego.v1

valid_azurerm_kubernetes_cluster_logging_enabled(resource) if {
    (resource.addon_profile.oms_agent.enabled == true) or (resource.oms_agent.log_analytics_workspace_id != null)
}

deny_aks_logging_enabled contains reason if {
    resource := data.utils.resource(input, "azurerm_kubernetes_cluster")[_]
    not valid_azurerm_kubernetes_cluster_logging_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_4: Ensure AKS logging to Azure Monitoring is Configured '%s' https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSLoggingEnabled.py", [resource.address])
}
