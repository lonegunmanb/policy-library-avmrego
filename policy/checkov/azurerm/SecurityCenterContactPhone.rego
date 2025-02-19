package checkov

import rego.v1

valid_azurerm_security_center_contact_phone_is_set(resource) if {
    resource.values.phone != null
}

deny_CKV_AZURE_20 contains reason if {
    resource := data.utils.resource(input, "azurerm_security_center_contact")[_]
    not valid_azurerm_security_center_contact_phone_is_set(resource)

    reason := sprintf("checkov/CKV_AZURE_20: Ensure that security contact 'Phone number' is set https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SecurityCenterContactPhone.py", [])
}
