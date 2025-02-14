package Azure_Proactive_Resiliency_Library_v2.migrate_vm_using_availability_sets_to_vmss_flex

import rego.v1

deny_migrate_vm_using_availability_sets_to_vmss_flex contains reason if {
    resource := data.utils.resource(input, "azurerm_windows_virtual_machine")[_]
    resource.values.availability_set_id

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2: '%s' `azurerm_linux_virtual_machine` must not define `availability_set_id`: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Compute/virtualMachines/#migrate-vms-using-availability-sets-to-vmss-flex", [resource.address])
}