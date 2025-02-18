package checkov

import rego.v1

valid_azurerm_instance_disable_password(resource) if {
  resource.resource_type == "azurerm_virtual_machine"
  (resource.os_profile_linux_config.disable_password_authentication == true)
}

valid_azurerm_instance_disable_password(resource) if {
  resource.resource_type == "azurerm_linux_virtual_machine"
  (resource.os_profile_linux_config.disable_password_authentication == true)
}

deny contains reason if {
  resource := input.resources[_]
  resource.resource_type == "azurerm_virtual_machine"
  not valid_azurerm_instance_disable_password(resource)
  reason := sprintf("checkov/CKV_AZURE_1: Ensure Azure Instance does not use basic authentication(Use SSH Key Instead) %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureInstancePassword.py", [resource.name])
}

deny contains reason if {
  resource := input.resources[_]
  resource.resource_type == "azurerm_linux_virtual_machine"
  not valid_azurerm_instance_disable_password(resource)
  reason := sprintf("checkov/CKV_AZURE_1: Ensure Azure Instance does not use basic authentication(Use SSH Key Instead) %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureInstancePassword.py", [resource.name])
}
