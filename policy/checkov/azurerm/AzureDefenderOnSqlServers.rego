package checkov

import rego.v1

valid_azurerm_security_center_subscription_pricing_defender_on(resource) if {
    resource.values.resource_type != "SqlServers"
}

valid_azurerm_security_center_subscription_pricing_defender_on(resource) if {
    resource.values.tier == "Standard"
}

deny_azure_defender_on_sql_servers contains reason if {
    resource := data.utils.resource(input, "azurerm_security_center_subscription_pricing")[_]
    not valid_azurerm_security_center_subscription_pricing_defender_on(resource)

    reason := sprintf("checkov/CKV_AZURE_69: Ensure that Azure Defender is set to On for Azure SQL database servers %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureDefenderOnSqlServers.py", [resource.address])
}
