package checkov

import rego.v1

valid_azurerm_app_service_java_version(resource) if {
    resource.values.site_config[0].java_version[0] == "11"
}

deny_CKV_AZURE_83 contains reason if {
    resource := data.utils.resource(input, "azurerm_app_service")[_]
    not valid_azurerm_app_service_java_version(resource)

    reason := sprintf("checkov/CKV_AZURE_83: Ensure that 'Java version' is the latest, if used to run the web app. Current value is '%v', Expected value is '11' https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceJavaVersion.py", [resource.values.site_config[0].java_version[0]])
}