package checkov

import rego.v1

valid_azurerm_storage_container_private_access(resource) if {
    resource.values.container_access_type[0] == "private"
}

deny_CKV_AZURE_34 contains reason if {
    resource := data.utils.resource(input, "azurerm_storage_container")[_]
    not valid_azurerm_storage_container_private_access(resource)

    reason := sprintf("checkov/CKV_AZURE_34: Ensure that 'Public access level' is set to Private for blob containers. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/StorageBlobServiceContainerPrivateAccess.py")
}
