package checkov

import rego.v1

valid_azurerm_web_application_firewall_policy_cve_2021_44228(resource) if {
    managed_rules := resource.values.managed_rules
    some i, rule in managed_rules {
        managed_rule_sets := rule.managed_rule_set
        some j, rule_set in managed_rule_sets {
            rule_set.type == "OWASP"
            rule_set.version == "3.1" || rule_set.version == "3.2"
            rule_overrides := rule_set.rule_group_override
            not contains_disabled_rule_944240(rule_overrides)
        }
    }
}

contains_disabled_rule_944240(rule_overrides) if {
    some k, rule_override in rule_overrides {
        rule_override.rule_group_name == "REQUEST-944-APPLICATION-ATTACK-JAVA"
        disabled_rules := rule_override.disabled_rules
        some l, disabled_rule in disabled_rules {
            disabled_rule == "944240"
        }
    }
}

deny_CKV_AZURE_135 contains reason if {
    resource := data.utils.resource(input, "azurerm_web_application_firewall_policy")[_]
    not valid_azurerm_web_application_firewall_policy_cve_2021_44228(resource)

    reason := sprintf("checkov/CKV_AZURE_135: Ensure Application Gateway WAF prevents message lookup in Log4j2. See CVE-2021-44228 aka log4jshell. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppGatewayWAFACLCVE202144228.py")
}
