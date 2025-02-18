package checkov

import rego.v1

valid_azurerm_app_service_python_version(resource) if {
    resource.values.site_config[0].python_version[0] == "3.4"
}

deny_app_service_python_version contains reason if {
    resource := data.utils.resource(input, "azurerm_app_service")[_]
    not valid_azurerm_app_service_python_version(resource)

    reason := sprintf("checkov/CKV_AZURE_82: Ensure that 'Python version' is the latest, if used to run the web app. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServicePythonVersion.py", [])
}
