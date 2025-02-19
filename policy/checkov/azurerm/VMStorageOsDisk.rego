package checkov

import rego.v1

valid_azurerm_vm_uses_managed_disks(resource) if {
  not resource.values.storage_os_disk
}

valid_azurerm_vm_uses_managed_disks(resource) if {
    not "vhd_uri" in resource.values.storage_os_disk[0]
}

valid_azurerm_vm_uses_managed_disks(resource) if {
    not resource.values.storage_data_disk
}

valid_azurerm_vm_uses_managed_disks(resource) if {
    not "vhd_uri" in resource.values.storage_data_disk[0]
}

deny_CKV_AZURE_92 contains reason if {
    resource := data.utils.resource(input, "azurerm_linux_virtual_machine")[_]
    not valid_azurerm_vm_uses_managed_disks(resource)

    reason := sprintf("checkov/CKV_AZURE_92: Ensure that Virtual Machines use managed disks. %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/VMStorageOsDisk.py", [resource.address])
}

deny_CKV_AZURE_92 contains reason if {
    resource := data.utils.resource(input, "azurerm_windows_virtual_machine")[_]
    not valid_azurerm_vm_uses_managed_disks(resource)

    reason := sprintf("checkov/CKV_AZURE_92: Ensure that Virtual Machines use managed disks. %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/VMStorageOsDisk.py", [resource.address])
}
