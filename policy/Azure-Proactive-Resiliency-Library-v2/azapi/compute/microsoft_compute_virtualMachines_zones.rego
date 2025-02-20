package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azapi_mission_critical_virtual_machine_should_use_zone(resource) if {
    count(resource.values.body.zones) > 0
}

valid_azapi_mission_critical_virtual_machine_should_use_zone(resource) if {
    resource.after_unknown.zones == resource.after_unknown.zones
}

deny_mission_critical_virtual_machine_should_use_zone contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.Compute/virtualMachines")
    not valid_azapi_mission_critical_virtual_machine_should_use_zone(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/mission_critical_virtual_machine_should_use_zone: '%s' `azapi_resource` must have configured `zones`: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Compute/virtualMachines/#deploy-vms-across-availability-zones", [resource.address])
}