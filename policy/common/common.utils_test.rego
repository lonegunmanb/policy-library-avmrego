package utils_test

import data.utils
import rego.v1

test_resource_plan_resource_changes if {
    # According to HashiCorp's document, on Terraform Cloud (HCP Terraform) the plan was wrapped under `plan` field in `input`: https://github.com/hashicorp/terraform-docs-common/blob/ef6f18fd22f78e9437fa7ac9ecb85295d51988a3/website/docs/cloud-docs/policy-enforcement/define-policies/opa.mdx?plain=1#L40
    _input := {
        "plan": {
            "resource_changes": [
                {
                    "address": "azurerm_cosmosdb_account.example",
                    "change": {
                        "after": {
                            "backup": [
                                {
                                    "type": "Continuous"
                                }
                            ]
                        }
                    },
                    "mode": "managed",
                    "type": "azurerm_cosmosdb_account"
                }
            ]
        }
    }
    resources := utils.resource(_input, "azurerm_cosmosdb_account")
    count(resources) == 1
    resource := resources[_]
    resource.address == "azurerm_cosmosdb_account.example"
    resource.values.backup[0].type == "Continuous"
    resource.mode == "managed"
    resource.type == "azurerm_cosmosdb_account"
}

test_resource_resource_changes if {
    _input := {
        "resource_changes": [
            {
                "address": "azurerm_cosmosdb_account.example",
                "change": {
                    "after": {
                        "backup": [
                            {
                                "type": "Continuous"
                            }
                        ]
                    }
                },
                "mode": "managed",
                "type": "azurerm_cosmosdb_account"
            }
        ]
    }
    resources := utils.resource(_input, "azurerm_cosmosdb_account")
    count(resources) == 1
    resource := resources[_]
    resource.address == "azurerm_cosmosdb_account.example"
    resource.values.backup[0].type == "Continuous"
    resource.mode == "managed"
    resource.type == "azurerm_cosmosdb_account"
}

test_resource_values_root_module_resources if {
    _input := {
        "values": {
            "root_module": {
                "resources": [
                    {
                        "address": "azurerm_cosmosdb_account.example",
                        "values": {
                            "backup": [
                                {
                                    "type": "Continuous"
                                }
                            ]
                        },
                        "mode": "managed",
                        "type": "azurerm_cosmosdb_account"
                    }
                ]
            }
        }
    }
    resources := utils.resource(_input, "azurerm_cosmosdb_account")
    count(resources) == 1
    resource := resources[_]
    resource.address == "azurerm_cosmosdb_account.example"
    resource.values.backup[0].type == "Continuous"
    resource.mode == "managed"
    resource.type == "azurerm_cosmosdb_account"
}

test_is_create_or_update if {
	data.utils.is_create_or_update(["create"])
	data.utils.is_create_or_update(["update", "create"])
	data.utils.is_create_or_update(["create", "update"])
	data.utils.is_create_or_update(["delete", "create"])
	data.utils.is_create_or_update(["delete", "update"])
	not data.utils.is_create_or_update(["create", "delete"])
	data.utils.is_create_or_update(["update"])
}

test_is_resource_create_or_update if {
	data.utils.is_resource_create_or_update({"change": {"actions": ["create"]}})
	data.utils.is_resource_create_or_update({"change": {"actions": ["update", "create"]}})
	data.utils.is_resource_create_or_update({"change": {"actions": ["create", "update"]}})
	data.utils.is_resource_create_or_update({"change": {"actions": ["delete", "create"]}})
	not data.utils.is_resource_create_or_update({"change": {"actions": ["create", "delete"]}})
	data.utils.is_resource_create_or_update({"change": {"actions": ["update"]}})
}