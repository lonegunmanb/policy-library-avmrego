package checkov

import rego.v1

valid_azurerm_frontdoor_enables_waf(resource) if {
    resource.values.frontend_endpoint[0].web_application_firewall_policy_link_id != null
}

deny_azure_frontdoor_enables_waf contains reason if {
    resource := data.utils.resource(input, "azurerm_frontdoor")[_]
    not valid_azurerm_frontdoor_enables_waf(resource)

    reason := sprintf("checkov/CKV_AZURE_121: Ensure that Azure Front Door enables WAF for %s. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureFrontDoorEnablesWAF.py", [resource.address])
}
