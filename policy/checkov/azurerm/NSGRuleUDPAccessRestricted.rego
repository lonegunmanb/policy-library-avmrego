package checkov

import rego.v1

INTERNET_ADDRESSES := {
    "0.0.0.0/0",
    "internet",
    "any"
}

valid_azurerm_nsg_rule_udp_access_restricted(resource) if {
    not (
        resource.protocol == "udp"
        resource.direction == "inbound"
        resource.access == "allow"
        INTERNET_ADDRESSES contains lower(resource.source_address_prefix)
    )
}

deny_CKV_AZURE_77 contains reason if {
    resource := input.resource.security_rule[_]
    not valid_azurerm_nsg_rule_udp_access_restricted(resource)

    reason := sprintf("checkov/CKV_AZURE_77: Ensure that UDP Services are restricted from the Internet. Resource %s allows UDP access from the internet. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/NSGRuleUDPAccessRestricted.py", [input.resource.name])
}

deny_CKV_AZURE_77 contains reason if {
    resource := input.resource
    resource.type == "Microsoft.Network/networkSecurityGroups"
    rules := [rule | rule := resource.properties.securityRules[_]]
    some rule in rules
    rule.properties.protocol == "UDP"
    rule.properties.direction == "Inbound"
    rule.properties.access == "Allow"
    lower(rule.properties.sourceAddressPrefix) == "internet"
    reason := sprintf("checkov/CKV_AZURE_77: Ensure that UDP Services are restricted from the Internet. Resource %s allows UDP access from the internet. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/NSGRuleUDPAccessRestricted.py", [resource.name])
}
