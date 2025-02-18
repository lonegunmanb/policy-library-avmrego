package checkov

import rego.v1

valid_azurerm_role_definition_no_custom_subscription_owner(resource) if {
    not resource.values.permissions[0].actions[_] == "*"
}

deny_custom_role_definition_subscription_owner contains reason if {
    resource := data.utils.resource(input, "azurerm_role_definition")[_]
    not valid_azurerm_role_definition_no_custom_subscription_owner(resource)

    reason := sprintf("checkov/CKV_AZURE_39: Ensure that no custom subscription owner roles are created %s https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/CutsomRoleDefinitionSubscriptionOwner.py", [resource.address])
}
