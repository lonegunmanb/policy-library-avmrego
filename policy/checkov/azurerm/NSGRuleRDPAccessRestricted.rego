package checkov

import rego.v1

valid_azurerm_nsg_rule_rdp_access_restricted(resource) if {
    not contains(resource.properties.destinationPortRanges, "3389")
    not contains(resource.properties.destination_port_ranges, "3389")
    not contains(resource.properties.destinationPortRange, "3389")
    not contains(resource.properties.destination_port_range, "3389")
    not contains(resource.properties.destinationAddressPrefixes, "Internet")
    not contains(resource.properties.destination_address_prefixes, "Internet")
    not contains(resource.properties.destinationAddressPrefix, "Internet")
    not contains(resource.properties.destination_address_prefix, "Internet")
    not contains(resource.properties.sourceAddressPrefixes, "Internet")
    not contains(resource.properties.source_address_prefixes, "Internet")
    not contains(resource.properties.sourceAddressPrefix, "Internet")
    not contains(resource.properties.source_address_prefix, "Internet")
    not contains(resource.properties.sourceAddressPrefixes, "*")
    not contains(resource.properties.source_address_prefixes, "*")
    not contains(resource.properties.sourceAddressPrefix, "*")
    not contains(resource.properties.source_address_prefix, "*")
    resource.properties.access == "Deny"
}

deny_CKV_AZURE_9 contains reason if {
    resource := input.resources[_]
    resource.type == "Microsoft.Network/networkSecurityGroups/securityRules"
    not valid_azurerm_nsg_rule_rdp_access_restricted(resource)

    reason := sprintf("checkov/CKV_AZURE_9: Ensure that RDP access is restricted from the internet. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/NSGRuleRDPAccessRestricted.py")
}
