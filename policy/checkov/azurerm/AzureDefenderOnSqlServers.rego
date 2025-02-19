package checkov

import rego.v1

valid_azurerm_security_center_subscription_pricing_defender(resource) if {
    resource.resource_type != "SqlServers"
}

valid_azurerm_security_center_subscription_pricing_defender(resource) if {
    resource.resource_type == "SqlServers"
    resource.tier == "Standard"
}

deny_CKV_AZURE_69 contains reason if {
    resource := input.resource.azurerm_security_center_subscription_pricing[_]
    not valid_azurerm_security_center_subscription_pricing_defender(resource)

    reason := sprintf("checkov/CKV_AZURE_69: Ensure that Azure Defender is set to On for Azure SQL database servers. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureDefenderOnSqlServers.py")
}
