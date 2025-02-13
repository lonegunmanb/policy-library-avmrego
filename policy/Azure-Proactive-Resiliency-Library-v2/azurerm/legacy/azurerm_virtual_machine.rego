package Azure_Proactive_Resiliency_Library_v2.use_nat_gateway_instead_of_outbound_rules_for_production_load_lalancer

import rego.v1

deny_legacy_virtual_machine_not_allowed contains reason if {
    resources := data.utils.resource(input, "azurerm_virtual_machine")
    count(resources) > 0
    reason := sprintf("Azure-Proactive-Resiliency-Library-v2: '%s' legacy resource `azurerm_virtual_machine` must not be used anymore, use `azurerm_linux_virtual_machine` or `azurerm_windows_virtual_machine` instead", [resource.address])
}