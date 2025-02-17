package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azurerm_public_ip_use_standard_sku_and_zone_redundant_ip(resource) if {
   resource.values.sku == "Standard"
   count(resource.values.zones) >= 2
}

deny_public_ip_use_standard_sku_and_zone_redundant_ip contains reason if {
    resource := data.utils.resource(input, "azurerm_public_ip")[_]
    not valid_azurerm_public_ip_use_standard_sku_and_zone_redundant_ip(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2: '%s' `azurerm_public_ip` must have configured `sku` to `\"Standard\"` and a `zones` that cotnains at least 2 zones: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/publicIPAddresses/#use-standard-sku-and-zone-redundant-ips-when-applicable", [resource.address])
}