package checkov

import rego.v1

valid_azurerm_app_service_uses_azure_files(resource) if {
    resource.values.storage_account[0].type == "AzureFiles"
}

deny_CKV_AZURE_88 contains reason if {
    resource := data.utils.resource(input, ["azurerm_app_service", "azurerm_linux_web_app", "azurerm_windows_web_app"])[_]
    not valid_azurerm_app_service_uses_azure_files(resource)

    reason := sprintf("checkov/CKV_AZURE_88: Ensure that app services use Azure Files. Resource %s uses %s instead of AzureFiles. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceUsedAzureFiles.py", [resource.address, resource.values.storage_account[0].type])
}
