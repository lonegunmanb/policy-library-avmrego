package checkov

import rego.v1

# Rule CKV_AZURE_203

INTERNET_ADDRESSES := ["*", "0.0.0.0", "<nw>/0", "/0", "internet", "any"]

valid_azurerm_network_security_rule_203(resource, port) if {
    not allow_inbound_access_from_internet(resource, port)
}

allow_inbound_access_from_internet(resource, port) if {
    access := lower(resource.access)
    direction := lower(resource.direction)
    protocol := lower(resource.protocol)

    access == "allow"
    direction == "inbound"
    protocol == "tcp" || protocol == "*"

    # Check destination port
    destination_port_valid(resource, port)

    # Check source address
    source_address_from_internet(resource)
}

destination_port_valid(resource, port) if {
    (resource.destination_port_range != null && is_port_in_range(resource.destination_port_range, port)) ||
    (resource.destination_port_ranges != null && any(resource.destination_port_ranges, func(range) {is_port_in_range(range, port)}))
}

is_port_in_range(port_range, port) if {
    re_match("^\\d+-\\d+$", port_range)
    start := to_number(split(port_range, "-")[0])
    end := to_number(split(port_range, "-")[1])
    port >= start
    port <= end
}

is_port_in_range(port_range, port) if {
    port_range == to_string(port) || port_range == "*"
}

source_address_from_internet(resource) if {
    (resource.source_address_prefix != null && lower(resource.source_address_prefix) == INTERNET_ADDRESSES[_]) ||
    (resource.source_address_prefixes != null && any(resource.source_address_prefixes, func(prefix) {lower(prefix) == INTERNET_ADDRESSES[_]}))
}

deny_CKV_AZURE_203 contains reason if {
    resource := data.utils.resource(input, "azurerm_network_security_rule")[_]
    port := 22  #Fixed port to check
    not valid_azurerm_network_security_rule_203(resource, port)

    reason := sprintf("checkov/CKV_AZURE_203: Network Security Rule allows port 22 access from internet on %s. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/NSGRulePortAccessRestricted.py", [resource.address])
}

deny_CKV_AZURE_203 contains reason if {
    resource := data.utils.resource(input, "azurerm_network_security_group")[_]
    # assuming the check should also apply to NSGs, but NSGs don't have the same attributes directly
    # need to iterate through the security rules within the NSG
    rules := resource.security_rule
    some i
    rule := rules[i]
    port := 22
    not valid_azurerm_network_security_rule_203(rule, port)
    reason := sprintf("checkov/CKV_AZURE_203: Network Security Group allows port 22 access from internet on %s. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/NSGRulePortAccessRestricted.py", [resource.address])
}
