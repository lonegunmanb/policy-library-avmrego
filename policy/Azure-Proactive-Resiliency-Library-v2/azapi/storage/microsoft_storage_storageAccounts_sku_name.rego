package Azure_Proactive_Resiliency_Library_v2

import rego.v1

valid_azapi_storage_accounts_are_zone_or_region_redundant(resource) if {
    not endswith(resource.values.body.sku.name, "LRS")
}

deny_storage_accounts_are_zone_or_region_redundant contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.Storage/storageAccounts")
    not valid_azapi_storage_accounts_are_zone_or_region_redundant(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2/storage_accounts_are_zone_or_region_redundant: '%s' `azapi_resource` must not have configured `sku.name` to `\"Standard_LRS\"` nor `\"Premium_LRS\"`: https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Storage/storageAccounts/#ensure-that-storage-accounts-are-zone-or-region-redundant", [resource.address])
}