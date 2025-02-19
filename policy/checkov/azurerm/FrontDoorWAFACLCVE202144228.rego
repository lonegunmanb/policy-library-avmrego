package checkov

import rego.v1

valid_azurerm_frontdoor_firewall_policy_cve_2021_44228(resource) if {
    managed_rules := resource.values.managed_rule
    some(managed_rules)
    managed_rule := managed_rules[_]
    managed_rule.type == "DefaultRuleSet" || managed_rule.type == "Microsoft_DefaultRuleSet"
    rule_overrides := managed_rule.override
    some(rule_overrides)
    rule_override := rule_overrides[_]
    rule_override.rule_group_name == "JAVA"
    rules := rule_override.rule
    some(rules)
    rule := rules[_]
    rule.rule_id == "944240"
    rule.enabled == true
    rule.action == "Block" || rule.action == "Redirect"
}

deny_CKV_AZURE_133 contains reason if {
    resource := data.utils.resource(input, "azurerm_frontdoor_firewall_policy")[_]
    not valid_azurerm_frontdoor_firewall_policy_cve_2021_44228(resource)
    reason := sprintf("checkov/CKV_AZURE_133: Ensure Front Door WAF prevents message lookup in Log4j2. See CVE-2021-44228 aka log4jshell. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/FrontDoorWAFACLCVE202144228.py")
}
