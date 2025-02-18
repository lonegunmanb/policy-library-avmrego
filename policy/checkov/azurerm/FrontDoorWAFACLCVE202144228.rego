package checkov

import rego.v1

valid_azurerm_frontdoor_firewall_policy_cve_2021_44228(resource) if {
    managed_rules := resource.values.managed_rule
    any(managed_rules, func(rule) {
        rule.type == "DefaultRuleSet" || rule.type == "Microsoft_DefaultRuleSet"
    })

    java_rules_exist := any(managed_rules, func(rule) {
        rule.type == "DefaultRuleSet" || rule.type == "Microsoft_DefaultRuleSet"
        rule_overrides := rule.override
        any(rule_overrides, func(override) {
            override.rule_group_name == "JAVA"
        })
    })

    all_java_rules_are_blocked_or_redirected := all(managed_rules, func(rule) {
        not (rule.type == "DefaultRuleSet" || rule.type == "Microsoft_DefaultRuleSet") || all(rule.override, func(override) {
            not (override.rule_group_name == "JAVA") || all(override.rule, func(r) {
                not (r.rule_id == "944240") || (r.enabled == true && (r.action == "Block" || r.action == "Redirect"))
            })
        })
    })
    java_rules_exist == true
    all_java_rules_are_blocked_or_redirected == true
}

deny_frontdoor_waf_acl_cve_2021_44228 contains reason if {
    resource := data.utils.resource(input, "azurerm_frontdoor_firewall_policy")[_]
    not valid_azurerm_frontdoor_firewall_policy_cve_2021_44228(resource)
    reason := sprintf("checkov/CKV_AZURE_133: Ensure Front Door WAF prevents message lookup in Log4j2. See CVE-2021-44228 aka log4jshell https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/FrontDoorWAFACLCVE202144228.py")
}
