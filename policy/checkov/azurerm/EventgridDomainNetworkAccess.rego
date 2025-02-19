package checkov

import rego.v1

valid_azurerm_eventgrid_domain_network_access_disabled(resource) if {
    resource.values.public_network_access_enabled == false
}

deny_CKV_AZURE_106 contains reason if {
    resource := data.utils.resource(input, "azurerm_eventgrid_domain")[_]
    not valid_azurerm_eventgrid_domain_network_access_disabled(resource)

    reason := sprintf("checkov/CKV_AZURE_106: Ensure that Azure Event Grid Domain public network access is disabled. Resource %s has public_network_access_enabled set to true. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/EventgridDomainNetworkAccess.py", [resource.address])
}
