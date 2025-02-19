package checkov

import rego.v1

valid_azurerm_security_group_rule_rdp_access_restricted(resource) if {
    not contains(resource.properties.destinationPortRange, "3389")
    not contains(resource.properties.destinationPortRanges, "3389")

}


deny_CKV_AZURE_9 contains reason if {
    resource := input.resources[_]
    resource.type == "Microsoft.Network/networkSecurityGroups/securityRules"
    resource.properties.direction == "Inbound"
    resource.properties.access == "Allow"

    not valid_azurerm_security_group_rule_rdp_access_restricted(resource)

    reason := sprintf("checkov/CKV_AZURE_9: Ensure that RDP access is restricted from the internet. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/NSGRuleRDPAccessRestricted.py")
}
