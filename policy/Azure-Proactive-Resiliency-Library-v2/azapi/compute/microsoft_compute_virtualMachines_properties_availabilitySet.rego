package Azure_Proactive_Resiliency_Library_v2.migrate_vm_using_availability_sets_to_vmss_flex

import rego.v1

valid_azapi_virtual_machine_properties_availabilitySet(resource) if {
    not resource.values.body.properties.availabilitySet
}

deny_migrate_vm_using_availability_sets_to_vmss_flex contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.Compute/virtualMachines")
    not valid_azapi_virtual_machine_properties_availabilitySet(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2: '%s' `azapi_resource` must not define `properties.availabilitySet`: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Compute/virtualMachines/#migrate-vms-using-availability-sets-to-vmss-flex", [resource.address])
}