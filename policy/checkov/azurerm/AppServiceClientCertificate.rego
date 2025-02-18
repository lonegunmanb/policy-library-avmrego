package checkov

import rego.v1

valid_azurerm_app_service_client_certificate_enabled(resource) if {
    resource.values.client_cert_enabled == true
}

valid_azurerm_linux_web_app_client_certificate_enabled(resource) if {
    resource.values.client_certificate_enabled == true
}

valid_azurerm_windows_web_app_client_certificate_enabled(resource) if {
    resource.values.client_certificate_enabled == true
}

deny contains reason if {
    resource := data.utils.resource(input, "azurerm_app_service")[_]
    not valid_azurerm_app_service_client_certificate_enabled(resource)
    reason := sprintf("checkov/CKV_AZURE_17: Ensure the web app has 'Client Certificates (Incoming client certificates)' set for azurerm_app_service %s. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceClientCertificate.py", [resource.address])
}

deny contains reason if {
    resource := data.utils.resource(input, "azurerm_linux_web_app")[_]
    not valid_azurerm_linux_web_app_client_certificate_enabled(resource)
    reason := sprintf("checkov/CKV_AZURE_17: Ensure the web app has 'Client Certificates (Incoming client certificates)' set for azurerm_linux_web_app %s. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceClientCertificate.py", [resource.address])
}

deny contains reason if {
    resource := data.utils.resource(input, "azurerm_windows_web_app")[_]
    not valid_azurerm_windows_web_app_client_certificate_enabled(resource)
    reason := sprintf("checkov/CKV_AZURE_17: Ensure the web app has 'Client Certificates (Incoming client certificates)' set for azurerm_windows_web_app %s. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/AppServiceClientCertificate.py", [resource.address])
}
