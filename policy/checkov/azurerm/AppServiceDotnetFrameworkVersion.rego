package checkov

import rego.v1

valid_azurerm_app_service_dotnet_framework_version(resource) if {
    not resource.values.site_config[0]
}

valid_azurerm_app_service_dotnet_framework_version(resource) if {
    resource.values.site_config[0].dotnet_framework_version == "v6.0"
}

deny_CKV_AZURE_80 contains reason if {
    resource := data.utils.resource(input, "azurerm_app_service")[_]
    not valid_azurerm_app_service_dotnet_framework_version(resource)

    reason := sprintf("checkov/CKV_AZURE_80: Ensure that 'Net Framework' version is the latest, if used as a part of the web app. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceDotnetFrameworkVersion.py")
}
