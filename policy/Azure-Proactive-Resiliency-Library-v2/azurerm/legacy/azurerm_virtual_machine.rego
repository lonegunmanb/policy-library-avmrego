package Azure_Proactive_Resiliency_Library_v2

import rego.v1

deny_legacy_virtual_machine_not_allowed contains reason if {
    resource := data.utils.resource(input, "azurerm_virtual_machine")[_]
    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/legacy_virtual_machine_not_allowed: '%s' legacy resource `azurerm_virtual_machine` must not be used anymore, use `azurerm_linux_virtual_machine` or `azurerm_windows_virtual_machine` instead", [resource.address])
}