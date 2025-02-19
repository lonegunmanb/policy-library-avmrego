package checkov

import rego.v1

valid_azurerm_postgresql_server_threat_detection_enabled(resource) if {
    resource.values.threat_detection_policy[0].enabled == true
}

deny_CKV_AZURE_128 contains reason if {
    resource := data.utils.resource(input, "azurerm_postgresql_server")[_]
    not valid_azurerm_postgresql_server_threat_detection_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_128: Ensure that PostgreSQL server enables Threat detection policy. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/PostgresSQLTreatDetectionEnabled.py", [])
}
