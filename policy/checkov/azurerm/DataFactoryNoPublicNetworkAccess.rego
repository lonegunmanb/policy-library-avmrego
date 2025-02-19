package checkov

import rego.v1

valid_azurerm_data_factory_no_public_network_access(resource) if {
    resource.values.public_network_enabled == false
}

deny_CKV_AZURE_104 contains reason if {
    resource := data.utils.resource(input, "azurerm_data_factory")[_]
    not valid_azurerm_data_factory_no_public_network_access(resource)

    reason := sprintf("checkov/CKV_AZURE_104: Ensure that Azure Data factory public network access is disabled. Resource %s should have public_network_enabled set to false. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/DataFactoryNoPublicNetworkAccess.py", [resource.address])
}
