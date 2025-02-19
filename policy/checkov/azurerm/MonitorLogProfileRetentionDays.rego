package checkov

import rego.v1

valid_azurerm_monitor_log_profile_retention_days(resource) if {
    retention_policy := resource.values.retention_policy
    count(retention_policy) > 0
    retention_policy[0].enabled == [true]
    retention_policy[0].days != null
    rego.to_number(retention_policy[0].days[0]) >= 365
}

valid_azurerm_monitor_log_profile_retention_days(resource) if {
    retention_policy := resource.values.retention_policy
    count(retention_policy) > 0
    retention_policy[0].enabled == [false]
    retention_policy[0].days != null
    rego.to_number(retention_policy[0].days) == 0
}


deny_CKV_AZURE_37 contains reason if {
    resource := data.utils.resource(input, "azurerm_monitor_log_profile")[_]
    not valid_azurerm_monitor_log_profile_retention_days(resource)

    reason := sprintf("checkov/CKV_AZURE_37: Ensure that Activity Log Retention is set 365 days or greater. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/MonitorLogProfileRetentionDays.py")
}
