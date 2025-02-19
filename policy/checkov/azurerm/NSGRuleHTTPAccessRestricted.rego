package checkov

import rego.v1

valid_azurerm_nsg_rule_http_access_restricted(resource) if {
    not (resource.values.access == "Allow" and resource.values.destination_port_range == "80")
}

deny_CKV_AZURE_160 contains reason if {
    resource := data.utils.resource(input, "azurerm_network_security_rule")[_]
    not valid_azurerm_nsg_rule_http_access_restricted(resource)

    reason := sprintf("checkov/CKV_AZURE_160: Ensure that HTTP (port 80) access is restricted from the internet. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/NSGRuleHTTPAccessRestricted.py", [])
}
