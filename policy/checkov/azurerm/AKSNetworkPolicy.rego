package checkov

import rego.v1

valid_azurerm_kubernetes_cluster_has_network_policy(resource) if {
    resource.values.network_profile[0].network_policy != null
}

deny_CKV_AZURE_7 contains reason if {
    resource := data.utils.resource(input, "azurerm_kubernetes_cluster")[_]
    not valid_azurerm_kubernetes_cluster_has_network_policy(resource)

    reason := sprintf("checkov/CKV_AZURE_7: Ensure AKS cluster has Network Policy configured %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSNetworkPolicy.py", [resource.address])
}
