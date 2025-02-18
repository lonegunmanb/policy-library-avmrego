package checkov

import rego.v1

valid_azurerm_web_application_firewall_policy_no_cve(resource) if {
    not waf_policy_has_cve(resource)
}

waf_policy_has_cve(resource) if {
    managed_rules := resource.values.managed_rules
    managed_rule_sets := managed_rules[0].managed_rule_set
    
    some(rule_set_idx, rule_set, managed_rule_sets)
    rule_set.type == "OWASP"
    rule_set.version == ["3.1"] || rule_set.version == ["3.2"]
    
    rule_overrides := rule_set.rule_group_override
    
    some(override_idx, override, rule_overrides)
    override.rule_group_name == ["REQUEST-944-APPLICATION-ATTACK-JAVA"]
    
    disabled_rules := override.disabled_rules
    some(disabled_idx, disabled, disabled_rules)
    contains(disabled, "944240")
}

deny_app_gateway_waf_acl_cve202144228 contains reason if {
    resource := data.utils.resource(input, "azurerm_web_application_firewall_policy")[_]
    not valid_azurerm_web_application_firewall_policy_no_cve(resource)

    reason := sprintf("checkov/CKV_AZURE_135: Ensure Application Gateway WAF prevents message lookup in Log4j2. See CVE-2021-44228 aka log4jshell https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppGatewayWAFACLCVE202144228.py")
}
