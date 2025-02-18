package checkov

import rego.v1

valid_azurerm_api_management_client_certs_enabled(resource) if {
    resource.values.sku_name == ["Consumption"]
    resource.values.client_certificate_enabled == [True]
}

deny_api_management_client_certs_enforced contains reason if {
    resource := data.utils.resource(input, "azurerm_api_management")[_]
    resource.values.sku_name == ["Consumption"]
    not valid_azurerm_api_management_client_certs_enabled(resource)

    reason := sprintf("checkov/CKV_AZURE_152: Ensure Client Certificates are enforced for API management %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/APIManagementCertsEnforced.py", [resource.address])
}
