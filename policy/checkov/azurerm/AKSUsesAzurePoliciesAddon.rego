package checkov

import rego.v1

valid_azurerm_kubernetes_cluster_azure_policy_addon_enabled(resource) if {
    resource.values.azure_policy_enabled == true
}

valid_azurerm_kubernetes_cluster_azure_policy_addon_enabled(resource) if {
    addon_profile := resource.values.addon_profile
    count(addon_profile) > 0
    azure_policy := addon_profile[0].azure_policy
    count(azure_policy) > 0
    azure_policy[0].enabled == true
}

deny_aks_uses_azure_policies_addon contains reason if {
    resource := data.utils.resource(input, "azurerm_kubernetes_cluster")[_]
    not valid_azurerm_kubernetes_cluster_azure_policy_addon_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_116: Ensure that AKS uses Azure Policies Add-on %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSUsesAzurePoliciesAddon.py", [resource.address])
}
