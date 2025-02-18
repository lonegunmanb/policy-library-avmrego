package checkov

import rego.v1

valid_azurerm_web_application_firewall_policy_enabled(resource) if {
    resource.policy_settings.enabled == true
}

deny_AppGWUseWAFMode contains reason if {
    resource := input.resource.azurerm_web_application_firewall_policy[_]
    not valid_azurerm_web_application_firewall_policy_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_122: Ensure that Application Gateway uses WAF in \"Detection\" or \"Prevention\" modes https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppGWUseWAFMode.py")
}
