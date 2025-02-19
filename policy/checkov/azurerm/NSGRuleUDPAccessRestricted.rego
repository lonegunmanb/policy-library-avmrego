package checkov

import rego.v1

INTERNET_ADDRESSES := ["0.0.0.0/0", "*"]

valid_azurerm_nsg_rule_udp_access_restricted(resource) if {
    not is_nsg_rule_allowing_udp_from_internet(resource)
}

is_nsg_rule_allowing_udp_from_internet(resource) if {
    rule := resource.security_rule[_]
    lower(rule.protocol) == "udp"
    lower(rule.direction) == "inbound"
    lower(rule.access) == "allow"
    contains(INTERNET_ADDRESSES, lower(rule.source_address_prefix))
}

is_nsg_rule_allowing_udp_from_internet(resource) if {
    lower(resource.protocol) == "udp"
    lower(resource.direction) == "inbound"
    lower(resource.access) == "allow"
    contains(INTERNET_ADDRESSES, lower(resource.source_address_prefix))
}

deny_CKV_AZURE_77 contains reason if {
    resource := data.utils.resource(input, "azurerm_network_security_group")[_]
    not valid_azurerm_nsg_rule_udp_access_restricted(resource)
    reason := sprintf("checkov/CKV_AZURE_77: Ensure that UDP Services are restricted from the Internet in azurerm_network_security_group '%s'. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/NSGRuleUDPAccessRestricted.py", [resource.address])
}

deny_CKV_AZURE_77 contains reason if {
    resource := data.utils.resource(input, "azurerm_network_security_rule")[_]
    not valid_azurerm_nsg_rule_udp_access_restricted(resource)
    reason := sprintf("checkov/CKV_AZURE_77: Ensure that UDP Services are restricted from the Internet in azurerm_network_security_rule '%s'. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/NSGRuleUDPAccessRestricted.py", [resource.address])
}