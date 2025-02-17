package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azapi_mission_critical_virtual_machine_should_use_premium_or_ultra_disks(resource) if {
    startswith(resource.values.body.properties.storageProfile.osDisk.managedDisk.storageAccountType, "Premium")
}

valid_azapi_mission_critical_virtual_machine_should_use_premium_or_ultra_disks(resource) if {
    startswith(resource.values.body.properties.storageProfile.osDisk.managedDisk.storageAccountType, "Ultra")
}

deny_mission_critical_virtual_machine_should_use_premium_or_ultra_disks contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.Compute/virtualMachines")
    not valid_azapi_mission_critical_virtual_machine_should_use_premium_or_ultra_disks(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/mission_critical_virtual_machine_should_use_premium_or_ultra_disks: '%s' `azapi_resource` must have configured `storageProfile.osDisk.managedDisk.storageAccountType` to use Premium or Ultra type: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Compute/virtualMachines/#mission-critical-workloads-should-consider-using-premium-or-ultra-disks", [resource.address])
}