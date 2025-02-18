package checkov

import rego.v1

valid_azurerm_linux_scale_set_password(resource) if {
    resource.values.disable_password_authentication[0] == true
}

deny_azure_scale_set_password contains reason if {
    resource := data.utils.resource(input, "azurerm_linux_virtual_machine_scale_set")[_]
    not valid_azurerm_linux_scale_set_password(resource)

    reason := sprintf("checkov/CKV_AZURE_49: Ensure Azure linux scale set does not use basic authentication(Use SSH Key Instead). https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AzureScaleSetPassword.py")
}
