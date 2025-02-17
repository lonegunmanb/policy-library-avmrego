package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azurerm_deny_migrate_vm_using_availability_sets_to_vmss_flex(_resource) if {
    not _resource.values.availability_set_id
}

valid_azurerm_deny_migrate_vm_using_availability_sets_to_vmss_flex(_resource) if {
    _resource.values.availability_set_id == null
}

deny_migrate_vm_using_availability_sets_to_vmss_flex contains reason if {
    resource := data.utils.resource(input, "azurerm_linux_virtual_machine")[_]
    not valid_azurerm_deny_migrate_vm_using_availability_sets_to_vmss_flex(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/migrate_vm_using_availability_sets_to_vmss_flex: '%s' `azurerm_linux_virtual_machine` must not define `availability_set_id`: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Compute/virtualMachines/#migrate-vms-using-availability-sets-to-vmss-flex", [resource.address])
}