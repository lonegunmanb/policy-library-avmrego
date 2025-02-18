package checkov

import rego.v1

valid_azurerm_app_service_uses_azure_files(resource) if {
    resource.values.storage_account[0].type == "AzureFiles"
}

deny_app_service_uses_azure_files contains reason if {
    resource := data.utils.resource(input, "azurerm_app_service")[_]

    not valid_azurerm_app_service_uses_azure_files(resource)

    reason := sprintf("checkov/CKV_AZURE_88: Ensure that app services use Azure Files. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceUsedAzureFiles.py")
}

deny_linux_web_app_uses_azure_files contains reason if {
    resource := data.utils.resource(input, "azurerm_linux_web_app")[_]

    not valid_azurerm_app_service_uses_azure_files(resource)

    reason := sprintf("checkov/CKV_AZURE_88: Ensure that app services use Azure Files. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceUsedAzureFiles.py")
}

deny_windows_web_app_uses_azure_files contains reason if {
    resource := data.utils.resource(input, "azurerm_windows_web_app")[_]

    not valid_azurerm_app_service_uses_azure_files(resource)

    reason := sprintf("checkov/CKV_AZURE_88: Ensure that app services use Azure Files. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceUsedAzureFiles.py")
}