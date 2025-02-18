package checkov

import rego.v1

INTERNET_ADDRESSES := ["*", "0.0.0.0", "<nw>/0", "/0", "internet", "any"]

# matches a port range
is_port_in_range(port, ports) = true if {
    re_match("^\\d+-\\d+$", ports)
    parts := strings.split(ports, "-")
    int(parts[0]) <= port
    port <= int(parts[1])
}

is_port_in_range(port, ports) = true if {
    ports == "*"
}

is_port_in_range(port, ports) = true if {
    int(ports) == port
}

valid_azurerm_nsg_rule_port_access_restricted(resource, port) if {
    not resource.values.access == "Allow"
}

valid_azurerm_nsg_rule_port_access_restricted(resource, port) if {
    not resource.values.direction == "Inbound"
}

valid_azurerm_nsg_rule_port_access_restricted(resource, port) if {
    not resource.values.protocol == "tcp"
    not resource.values.protocol == "*"
}

valid_azurerm_nsg_rule_port_access_restricted(resource, port) if {
    not any(is_port_in_range(port, p)) {
        p := resource.values.destination_port_range
    }
}

valid_azurerm_nsg_rule_port_access_restricted(resource, port) if {
    not any(is_port_in_range(port, p)) {
        resource.values.destination_port_ranges
        p := resource.values.destination_port_ranges[_]
    }
}

valid_azurerm_nsg_rule_port_access_restricted(resource, port) if {
    not any(strings.lower(prefix) == addr, INTERNET_ADDRESSES) {
        prefix := resource.values.source_address_prefix
        addr := prefix
    }
}

valid_azurerm_nsg_rule_port_access_restricted(resource, port) if {
    not any(strings.lower(prefix) == addr, INTERNET_ADDRESSES) {
        resource.values.source_address_prefixes
        prefixes := resource.values.source_address_prefixes[_]
        addr := prefixes[_]
        prefix := addr
    }
}

deny_NSGRulePortAccessRestricted contains reason if {
    resource := data.utils.resource(input, "azurerm_network_security_rule")[_]
    port := 80 # default port, the python code takes port as input
    not valid_azurerm_nsg_rule_port_access_restricted(resource, port)

    reason := sprintf("checkov/NSGRulePortAccessRestricted: Network Security Group Rule allows insecure port access for port %v at %s. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/NSGRulePortAccessRestricted.py", [port, resource.address])
}

deny_NSGRulePortAccessRestricted contains reason if {
    resource := data.utils.resource(input, "azurerm_network_security_group")[_]
    port := 80 # default port, the python code takes port as input
    rules := resource.values.security_rule
    not valid_azurerm_nsg_rule_port_access_restricted(rules[_], port)

    reason := sprintf("checkov/NSGRulePortAccessRestricted: Network Security Group Rule allows insecure port access for port %v at %s. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/NSGRulePortAccessRestricted.py", [port, resource.address])
}
