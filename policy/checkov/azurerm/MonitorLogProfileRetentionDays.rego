package checkov

import rego.v1

valid_azurerm_monitor_log_profile_retention_days(resource) if {
    retention_policy := resource.values.retention_policy

    # Case 1: retention_policy is not defined, which is considered a failure according to the check.
    not is_null(retention_policy)

    # Case 2: retention_policy is defined and enabled.
    retention_policy[0].enabled == [true]
    int(retention_policy[0].days[0]) >= 365
}

valid_azurerm_monitor_log_profile_retention_days(resource) if {
    retention_policy := resource.values.retention_policy
    # Case 3: retention_policy is defined and not enabled, and days is set to 0
    retention_policy[0].enabled == [false]
    retention_policy[0].days == [0]
}

deny_monitor_log_profile_retention_days contains reason if {
    resource := data.utils.resource(input, "azurerm_monitor_log_profile")[_]
    not valid_azurerm_monitor_log_profile_retention_days(resource)

    reason := sprintf("checkov/CKV_AZURE_37: Ensure that Activity Log Retention is set 365 days or greater. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/MonitorLogProfileRetentionDays.py")
}
