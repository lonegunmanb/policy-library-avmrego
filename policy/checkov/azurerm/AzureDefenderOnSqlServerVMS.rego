package checkov

import rego.v1

valid_azurerm_security_center_subscription_pricing(resource) if {
    resource.values.resource_type != "SqlServerVirtualMachines"
}

valid_azurerm_security_center_subscription_pricing(resource) if {
    resource.values.tier == "Standard"
}

deny_CKV_AZURE_79 contains reason if {
    resource := data.utils.resource(input, "azurerm_security_center_subscription_pricing")[_]
    not valid_azurerm_security_center_subscription_pricing(resource)

    reason := sprintf("checkov/CKV_AZURE_79: Ensure that Azure Defender is set to On for SQL servers on machines. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureDefenderOnSqlServerVMS.py")
}
