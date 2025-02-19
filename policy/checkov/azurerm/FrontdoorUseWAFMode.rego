package checkov

import rego.v1

valid_azurerm_frontdoor_firewall_policy_enabled(resource) if {
    resource.values.policy_settings[0].enabled[0] == true
}

deny_CKV_AZURE_123 contains reason if {
    resource := data.utils.resource(input, "azurerm_frontdoor_firewall_policy")[_]
    not valid_azurerm_frontdoor_firewall_policy_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_123: Ensure that Azure Front Door uses WAF in \"Detection\" or \"Prevention\" modes. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/FrontdoorUseWAFMode.py")
}
