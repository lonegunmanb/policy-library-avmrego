package checkov

import rego.v1

valid_azurerm_eventgrid_domain_network_access(resource) if {
    resource.values.public_network_access_enabled == false
}

deny_eventgrid_domain_network_access contains reason if {
    resource := data.utils.resource(input, "azurerm_eventgrid_domain")[_]
    not valid_azurerm_eventgrid_domain_network_access(resource)

    reason := sprintf("checkov/CKV_AZURE_106: Ensure that Azure Event Grid Domain public network access is disabled. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/EventgridDomainNetworkAccess.py")
}
