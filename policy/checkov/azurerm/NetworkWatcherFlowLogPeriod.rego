package checkov

import rego.v1

valid_azurerm_network_watcher_flow_log_period(resource) if {
    retention_policy := resource.properties.retentionPolicy
    retention_policy.enabled == true
    days := retention_policy.days
    (days == 0) or (days >= 90)
}

deny_CKV_AZURE_12 contains reason if {
    resource := input.resourceChanges[_].after
    resource.type == "Microsoft.Network/networkWatchers/flowLogs"
    not valid_azurerm_network_watcher_flow_log_period(resource)
    reason := sprintf("checkov/CKV_AZURE_12: Ensure that Network Security Group Flow Log retention period is 'greater than 90 days' https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/NetworkWatcherFlowLogPeriod.py")
}
