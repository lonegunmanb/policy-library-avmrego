package checkov

import rego.v1

valid_azurerm_app_service_php_version(resource) if {
    resource.values.site_config[0].php_version[0] == "7.4"
}

deny_CKV_AZURE_81 contains reason if {
    resource := data.utils.resource(input, "azurerm_app_service")[_]
    not valid_azurerm_app_service_php_version(resource)

    reason := sprintf("checkov/CKV_AZURE_81: Ensure that 'PHP version' is the latest, if used to run the web app. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServicePHPVersion.py")
}
