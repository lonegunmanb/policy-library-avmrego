package checkov

import rego.v1

valid_azurerm_key_vault_enables_firewall_rules_settings(resource) if {
    resource.values.network_acls[0].default_action == "Deny"
}

deny_CKV_AZURE_109 contains reason if {
    resource := data.utils.resource(input, "azurerm_key_vault")[_]
    not valid_azurerm_key_vault_enables_firewall_rules_settings(resource)

    reason := sprintf("checkov/CKV_AZURE_109: Ensure that key vault allows firewall rules settings. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/KeyVaultEnablesFirewallRulesSettings.py", [])
}
