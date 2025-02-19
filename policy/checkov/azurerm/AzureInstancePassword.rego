package checkov

import rego.v1

valid_azurerm_instance_password(resource) if {
    resource.disable_password_authentication == true
}

valid_azurerm_instance_password(resource) if {
    resource.os_profile_linux_config.disable_password_authentication == true
}

deny_CKV_AZURE_1 contains reason if {
    resource := input.resource
    resource.resource_type == "azurerm_virtual_machine"
    not valid_azurerm_instance_password(resource)

    reason := sprintf("checkov/CKV_AZURE_1: Ensure Azure Instance does not use basic authentication(Use SSH Key Instead). https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureInstancePassword.py")
}

deny_CKV_AZURE_1 contains reason if {
    resource := input.resource
    resource.resource_type == "azurerm_linux_virtual_machine"
    not valid_azurerm_instance_password(resource)
    reason := sprintf("checkov/CKV_AZURE_1: Ensure Azure Instance does not use basic authentication(Use SSH Key Instead). https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureInstancePassword.py")
}
