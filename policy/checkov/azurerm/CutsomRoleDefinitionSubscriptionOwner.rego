package checkov

import rego.v1

valid_azurerm_role_definition_no_subscription_owner(resource) if {
    not contains(resource.permissions[0].actions, "*")
}

deny_CKV_AZURE_39 contains reason if {
    resource := input.resource.azurerm_role_definition[_]
    not valid_azurerm_role_definition_no_subscription_owner(resource)

    reason := sprintf("checkov/CKV_AZURE_39: Ensure that no custom subscription owner roles are created %s", ["https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/CutsomRoleDefinitionSubscriptionOwner.py"])
}
