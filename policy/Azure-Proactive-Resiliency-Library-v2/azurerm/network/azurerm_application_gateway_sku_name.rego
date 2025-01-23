package Azure_Proactive_Resiliency_Library_v2.azurerm_application_gateway

valid_sku(resource) {
    resource.change.after.sku[_].name == "Standard_v2"
}

valid_sku(resource) {
    resource.change.after.sku[_].name == "WAF_v2"
}

deny[reason] {
    tfplan := data.utils.tfplan(input)
    resource := tfplan.resource_changes[_]
    resource.mode == "managed"
    resource.type == "azurerm_application_gateway"
    data.utils.is_create_or_update(resource.change.actions)
    not valid_sku(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2: '%s' `azurerm_application_gateway` must have 'sku.name' set to 'Standard_v2' or 'WAF_v2': https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/applicationGateways/#migrate-to-application-gateway-v2", [resource.address])
}