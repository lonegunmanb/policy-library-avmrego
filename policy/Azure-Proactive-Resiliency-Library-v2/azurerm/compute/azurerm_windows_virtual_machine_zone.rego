package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azurerm_windows_mission_critical_virtual_machine_should_use_zone(resource) if {
    resource.values.zone == resource.values.zone
}

deny_mission_critical_virtual_machine_should_use_zone contains reason if {
    resource := data.utils.resource(input, "azurerm_windows_virtual_machine")[_]
    not valid_azurerm_windows_mission_critical_virtual_machine_should_use_zone(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/mission_critical_virtual_machine_should_use_zone: '%s' `azurerm_windows_virtual_machine` must have configured `zone`: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Compute/virtualMachines/#deploy-vms-across-availability-zones", [resource.address])
}