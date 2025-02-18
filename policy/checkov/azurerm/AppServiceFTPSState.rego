package checkov

import rego.v1

valid_azurerm_app_service_ftps_state(resource) if {
    resource.values.site_config[0].ftps_state == "Disabled"
}

valid_azurerm_app_service_ftps_state(resource) if {
    resource.values.site_config[0].ftps_state == "FtpsOnly"
}

deny_app_service_ftps_state contains reason if {
    resource := data.utils.resource(input, "azurerm_app_service")[_]
    not valid_azurerm_app_service_ftps_state(resource)

    reason := sprintf("checkov/CKV_AZURE_78: Ensure FTP deployments are disabled for azurerm_app_service %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceFTPSState.py", [resource.address])
}

deny_linux_web_app_ftps_state contains reason if {
    resource := data.utils.resource(input, "azurerm_linux_web_app")[_]
    not valid_azurerm_app_service_ftps_state(resource)

    reason := sprintf("checkov/CKV_AZURE_78: Ensure FTP deployments are disabled for azurerm_linux_web_app %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceFTPSState.py", [resource.address])
}

deny_windows_web_app_ftps_state contains reason if {
    resource := data.utils.resource(input, "azurerm_windows_web_app")[_]
    not valid_azurerm_app_service_ftps_state(resource)

    reason := sprintf("checkov/CKV_AZURE_78: Ensure FTP deployments are disabled for azurerm_windows_web_app %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceFTPSState.py", [resource.address])
}
