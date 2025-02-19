package checkov

import rego.v1

valid_azurerm_machine_learning_compute_cluster_local_auth_disabled(resource) if {
    resource.values.local_auth_enabled == false
}

deny_CKV_AZURE_142 contains reason if {
    resource := data.utils.resource(input, "azurerm_machine_learning_compute_cluster")[_]
    not valid_azurerm_machine_learning_compute_cluster_local_auth_disabled(resource)

    reason := sprintf("checkov/CKV_AZURE_142: Ensure Machine Learning Compute Cluster Local Authentication is disabled. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/MLCCLADisabled.py")
}
