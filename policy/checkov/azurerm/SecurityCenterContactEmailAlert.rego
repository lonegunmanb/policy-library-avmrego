package checkov

import rego.v1

valid_azurerm_security_center_contact_alert_notifications(resource) if {
    resource.values.alert_notifications == true
}

deny_CKV_AZURE_21 contains reason if {
    resource := data.utils.resource(input, "azurerm_security_center_contact")[_]
    not valid_azurerm_security_center_contact_alert_notifications(resource)

    reason := sprintf("checkov/CKV_AZURE_21: Ensure that 'Send email notification for high severity alerts' is set to 'On' for azurerm_security_center_contact %s. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SecurityCenterContactEmailAlert.py", [resource.address])
}
