package checkov

import rego.v1

valid_azurerm_vm_scale_set_auto_os_patching(resource) if {
    resource.values.automatic_os_upgrade == true
    resource.values.os_profile_windows_config[_].enable_automatic_upgrades == true
}

deny_CKV_AZURE_95 contains reason if {
    resource := data.utils.resource(input, "azurerm_virtual_machine_scale_set")[_]
    not valid_azurerm_vm_scale_set_auto_os_patching(resource)

    reason := sprintf("checkov/CKV_AZURE_95: Ensure that automatic OS image patching is enabled for Virtual Machine Scale Sets %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/VMScaleSetsAutoOSImagePatchingEnabled.py", [resource.address])
}
