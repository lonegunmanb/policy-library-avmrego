package checkov

import rego.v1

valid_azurerm_nsg_rule_http_access_restricted(resource) if {
    not contains(resource.properties.destinationPortRanges, "80")
    not contains(resource.properties.destinationPortRange, "80")
    resource.properties.destinationPort != 80
}

deny_nsg_rule_http_access_restricted contains reason if {
    resource := input.resources[_]
    resource.type == "Microsoft.Network/networkSecurityGroups/securityRules"
    not valid_azurerm_nsg_rule_http_access_restricted(resource)

    reason := sprintf("checkov/CKV_AZURE_160: Ensure that HTTP (port 80) access is restricted from the internet. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/NSGRuleHTTPAccessRestricted.py")
}
