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

test_resource_values_child_module_resources if {
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
                ],
                "child_modules": [
                    {
                        "address": "module.sub",
                        "resources": [
                            {
                                "address": "module.sub.null_resource.res",
                                "mode": "managed",
                                "type": "null_resource",
                                "values": {
                                    "id": "2822366925496045444",
                                    "triggers": null
                                },
                            }
                        ]
                    },
                    {
                        "address": "module.sub2",
                        "resources": [
                            {
                                "address": "module.sub2.null_resource.res",
                                "mode": "managed",
                                "type": "null_resource",
                                "values": {
                                    "id": "2822366925496045445",
                                    "triggers": null
                                },
                            }
                        ]
                    },
                ]
            }
        }
    }
    cosmosdb_resources := utils.resource(_input, "azurerm_cosmosdb_account")
    count(cosmosdb_resources) == 1
    cosmosdb := cosmosdb_resources[_]
    cosmosdb.address == "azurerm_cosmosdb_account.example"
    cosmosdb.values.backup[0].type == "Continuous"
    cosmosdb.mode == "managed"
    cosmosdb.type == "azurerm_cosmosdb_account"

    null_resources := utils.resource(_input, "null_resource")
    count(null_resources) == 2
    null_resource := null_resources[1]
    null_resource.address == "module.sub2.null_resource.res"
    null_resource.values.id == "2822366925496045445"
    null_resource.mode == "managed"
    null_resource.type == "null_resource"
}

test_resource_values_child_module_resources_only if {
    _input := {
        "values": {
            "root_module": {
                "child_modules": [
                    {
                        "address": "module.sub",
                        "resources": [
                            {
                                "address": "module.sub.null_resource.res",
                                "mode": "managed",
                                "type": "null_resource",
                                "values": {
                                    "id": "2822366925496045444",
                                    "triggers": null
                                },
                            }
                        ]
                    },
                    {
                        "address": "module.sub2",
                        "resources": [
                            {
                                "address": "module.sub2.null_resource.res",
                                "mode": "managed",
                                "type": "null_resource",
                                "values": {
                                    "id": "2822366925496045445",
                                    "triggers": null
                                },
                            }
                        ]
                    },
                ]
            }
        }
    }
    null_resources := utils.resource(_input, "null_resource")
    count(null_resources) == 2
    null_resource := null_resources[1]
    null_resource.address == "module.sub2.null_resource.res"
    null_resource.values.id == "2822366925496045445"
    null_resource.mode == "managed"
    null_resource.type == "null_resource"
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

test_is_azure_type if {
    # Test case: resource type matches the specified Azure type
    utils.is_azure_type({"type": "Microsoft.DocumentDB/databaseAccounts@2024-12-01-preview"}, "Microsoft.DocumentDB/databaseAccounts")

    # Test case: resource type does not match the specified Azure type
    r := {"type": "Microsoft.Network/loadBalancers@2024-12-01-preview"}
    azure_type := "Microsoft.DocumentDB/databaseAccounts"
    not utils.is_azure_type({"type": "Microsoft.Network/loadBalancers@2024-12-01-preview"}, "Microsoft.DocumentDB/databaseAccounts")

    # Test case: resource type matches a different Azure type
   utils.is_azure_type({"type": "Microsoft.Network/loadBalancers@2024-12-01-preview"}, "Microsoft.Network/loadBalancers")

    # Test case: resource type does not match any Azure type
    not utils.is_azure_type({"type": "Custom.ResourceType@2024-12-01-preview"}, "Microsoft.DocumentDB/databaseAccounts")
}