package checkov

import rego.v1

valid_azurerm_kubernetes_cluster_api_server_authorized_ip_ranges(resource) if {
    resource.values.private_cluster_enabled == true
}

valid_azurerm_kubernetes_cluster_api_server_authorized_ip_ranges(resource) if {
    count(resource.values.api_server_authorized_ip_ranges) > 0
}

deny_CKV_AZURE_6 contains reason if {
    resource := data.utils.resource(input, "azurerm_kubernetes_cluster")[_]
    not valid_azurerm_kubernetes_cluster_api_server_authorized_ip_ranges(resource)

    reason := sprintf("checkov/CKV_AZURE_6: Ensure AKS has an API Server Authorized IP Ranges enabled %s", [resource.address])
    reason := reason + " https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AKSApiServerAuthorizedIpRanges.py"
}
