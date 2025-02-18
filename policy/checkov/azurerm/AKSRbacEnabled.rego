package checkov

import rego.v1

valid_azurerm_aks_rbac_enabled(resource) if {
    resource.role_based_access_control_enabled == true
}

valid_azurerm_aks_rbac_enabled(resource) if {
    resource.role_based_access_control[0].enabled == true
}

deny contains reason if {
    resource := input.resource.azurerm_kubernetes_cluster[_]
    not valid_azurerm_aks_rbac_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_5: Ensure RBAC is enabled on AKS clusters. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSRbacEnabled.py")
}
