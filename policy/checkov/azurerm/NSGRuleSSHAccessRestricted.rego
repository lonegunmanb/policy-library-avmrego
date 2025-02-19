package checkov

import rego.v1

valid_azurerm_security_group_rule_ssh_access_restricted(resource) if {
    not contains(resource.values.destination_port_ranges, "22")
    not contains(resource.values.destination_port_range, "22")
    not contains(resource.values.source_address_prefix, "Internet")
    not contains(resource.values.source_address_prefix, "0.0.0.0/0")
    not contains(resource.values.source_address_prefix, "*")
    resource.values.access == "Deny"
}

deny_CKV_AZURE_10 contains reason if {
    resource := data.utils.resource(input, "azurerm_network_security_rule")[_]
    resource.values.direction == "Inbound"
    resource.values.protocol == "Tcp"
    not valid_azurerm_security_group_rule_ssh_access_restricted(resource)

    reason := sprintf("checkov/CKV_AZURE_10: Ensure that SSH access is restricted from the internet. Rule %s allows unrestricted SSH access. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/NSGRuleSSHAccessRestricted.py", [resource.address])
}
