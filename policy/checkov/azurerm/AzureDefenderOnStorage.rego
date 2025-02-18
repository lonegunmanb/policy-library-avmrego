package checkov

import rego.v1

valid_azurerm_security_center_subscription_pricing_is_defender_on_storage(resource) if {
    resource.values.resource_type != "StorageAccounts"
}

valid_azurerm_security_center_subscription_pricing_is_defender_on_storage(resource) if {
    resource.values.tier == "Standard"
}

deny_azure_defender_on_storage contains reason if {
    resource := data.utils.resource(input, "azurerm_security_center_subscription_pricing")[_]
    not valid_azurerm_security_center_subscription_pricing_is_defender_on_storage(resource)

    reason := sprintf("checkov/CKV_AZURE_84: Ensure that Azure Defender is set to On for Storage. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureDefenderOnStorage.py")
}
