package checkov

import rego.v1

valid_azurerm_nsg_rule_ssh_access_restricted(resource) if {
    not resource.values.access == "Allow"
}

valid_azurerm_nsg_rule_ssh_access_restricted(resource) if {
    not resource.values.destination_port_ranges contains "22"
    not resource.values.destination_port_range == "22"
}

valid_azurerm_nsg_rule_ssh_access_restricted(resource) if {
    not resource.values.source_address_prefix == "*"
    not resource.values.source_address_prefixes contains "*"
    not resource.values.source_address_prefix == "Internet"
    not resource.values.source_address_prefixes contains "Internet"
    not resource.values.source_address_prefix == "0.0.0.0/0"
    not resource.values.source_address_prefixes contains "0.0.0.0/0"
}

deny_CKV_AZURE_10 contains reason if {
    resource := data.utils.resource(input, "azurerm_network_security_rule")[_]
    not valid_azurerm_nsg_rule_ssh_access_restricted(resource)

    reason := sprintf("checkov/CKV_AZURE_10: Ensure that SSH access is restricted from the internet. Resource %s allows unrestricted SSH access. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/NSGRuleSSHAccessRestricted.py", [resource.address])
}
