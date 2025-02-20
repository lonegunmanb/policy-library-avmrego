package Azure_Proactive_Resiliency_Library_v2

import rego.v1

azurerm_linux_availability_set_id_present(_resource) if {
    _resource.values.availability_set_id != null
}

azurerm_linux_availability_set_id_present(_resource) if {
    _resource.after_unknown.availability_set_id == _resource.after_unknown.availability_set_id
}

deny_migrate_vm_using_availability_sets_to_vmss_flex contains reason if {
    resource := data.utils.resource(input, "azurerm_linux_virtual_machine")[_]
    azurerm_linux_availability_set_id_present(resource)
    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/migrate_vm_using_availability_sets_to_vmss_flex: '%s' `azurerm_linux_virtual_machine` must not define `availability_set_id`: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Compute/virtualMachines/#migrate-vms-using-availability-sets-to-vmss-flex", [resource.address])
}