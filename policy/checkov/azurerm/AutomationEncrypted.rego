package checkov

import rego.v1

valid_azurerm_automation_variable_encrypted(resource) if {
    resource.values.encrypted == true
}

deny_CKV_AZURE_73 contains reason if {
    resource := data.utils.resource(input, "azurerm_automation_variable_bool")[_]
	not valid_azurerm_automation_variable_encrypted(resource)
    reason := sprintf("checkov/CKV_AZURE_73: Automation account variables should be encrypted. Resource %s is not encrypted. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AutomationEncrypted.py", [resource.address])
}

deny_CKV_AZURE_73 contains reason if {
    resource := data.utils.resource(input, "azurerm_automation_variable_string")[_]
	not valid_azurerm_automation_variable_encrypted(resource)
    reason := sprintf("checkov/CKV_AZURE_73: Automation account variables should be encrypted. Resource %s is not encrypted. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AutomationEncrypted.py", [resource.address])
}

deny_CKV_AZURE_73 contains reason if {
    resource := data.utils.resource(input, "azurerm_automation_variable_int")[_]
	not valid_azurerm_automation_variable_encrypted(resource)
    reason := sprintf("checkov/CKV_AZURE_73: Automation account variables should be encrypted. Resource %s is not encrypted. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AutomationEncrypted.py", [resource.address])
}

deny_CKV_AZURE_73 contains reason if {
    resource := data.utils.resource(input, "azurerm_automation_variable_datetime")[_]
	not valid_azurerm_automation_variable_encrypted(resource)
    reason := sprintf("checkov/CKV_AZURE_73: Automation account variables should be encrypted. Resource %s is not encrypted. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AutomationEncrypted.py", [resource.address])
}
