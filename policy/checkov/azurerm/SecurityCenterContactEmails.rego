package checkov

import rego.v1

valid_azurerm_security_center_contact_email(resource) if {
    resource.values.email != null
}

deny_CKV_AZURE_131 contains reason if {
    resource := data.utils.resource(input, "azurerm_security_center_contact")[_]
    not valid_azurerm_security_center_contact_email(resource)

    reason := sprintf("checkov/CKV_AZURE_131: Ensure that 'Security contact emails' is set https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SecurityCenterContactEmails.py", [])
}