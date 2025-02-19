package checkov

import rego.v1

valid_azurerm_mssql_server_security_alert_policy_email_account_admins_enabled(resource) if {
    resource.values.email_account_admins == "Enabled"
}

deny_CKV_AZURE_27 contains reason if {
    resource := data.utils.resource(input, "azurerm_mssql_server_security_alert_policy")[_]
    not valid_azurerm_mssql_server_security_alert_policy_email_account_admins_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_27: Ensure that 'Email service and co-administrators' is 'Enabled' for MSSQL servers %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/SQLServerEmailAlertsToAdminsEnabled.py", [resource.address])
}
