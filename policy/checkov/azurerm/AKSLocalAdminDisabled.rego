package checkov

import rego.v1

valid_azurerm_kubernetes_cluster_local_admin_disabled(resource) if {
    resource.values.local_account_disabled == true
}

deny_CKV_AZURE_141 contains reason if {
    resource := data.utils.resource(input, "azurerm_kubernetes_cluster")[_]
    not valid_azurerm_kubernetes_cluster_local_admin_disabled(resource)

    reason := sprintf("checkov/CKV_AZURE_141: Ensure AKS local admin account is disabled %s", ["https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSLocalAdminDisabled.py"])
}
