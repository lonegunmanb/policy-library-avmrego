package checkov

import rego.v1

valid_azurerm_web_application_firewall_policy_enabled(resource) if {
    resource.values.policy_settings[_].enabled[_] == true
}

deny_CKV_AZURE_122 contains reason if {
    resource := data.utils.resource(input, "azurerm_web_application_firewall_policy")[_]
    not valid_azurerm_web_application_firewall_policy_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_122: Ensure that Application Gateway uses WAF in \"Detection\" or \"Prevention\" modes %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppGWUseWAFMode.py", [resource.address])
}
