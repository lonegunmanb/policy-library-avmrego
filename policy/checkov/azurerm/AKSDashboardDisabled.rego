package checkov

import rego.v1

valid_azurerm_kubernetes_cluster_dashboard_disabled(resource) if {
    addon_profile := resource.values.addon_profile
    not is_object(addon_profile)
}

valid_azurerm_kubernetes_cluster_dashboard_disabled(resource) if {
    addon_profile := resource.values.addon_profile
    is_object(addon_profile)
    not addon_profile.kube_dashboard.enabled
}

deny_CKV_AZURE_8 contains reason if {
    resource := data.utils.resource(input, "azurerm_kubernetes_cluster")[_]
    not valid_azurerm_kubernetes_cluster_dashboard_disabled(resource)

    reason := sprintf("checkov/CKV_AZURE_8: Ensure Kubernetes Dashboard is disabled. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSDashboardDisabled.py")
}
