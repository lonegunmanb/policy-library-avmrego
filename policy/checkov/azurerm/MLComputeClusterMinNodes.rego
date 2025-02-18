package checkov

import rego.v1

valid_azurerm_ml_compute_cluster_min_nodes(resource) if {
    resource.values.scale_settings[0].min_node_count == 0
}

deny_azurerm_ml_compute_cluster_min_nodes contains reason if {
    resource := data.utils.resource(input, "azurerm_machine_learning_compute_cluster")[_]
    not valid_azurerm_ml_compute_cluster_min_nodes(resource)

    reason := sprintf("checkov/CKV_AZURE_150: Ensure Machine Learning Compute Cluster Minimum Nodes Set To 0. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/MLComputeClusterMinNodes.py")
}
