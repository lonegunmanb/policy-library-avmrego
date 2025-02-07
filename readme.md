# Azure Rego Policies

This repository contains some [Rego](https://www.openpolicyagent.org/) policy files designed for Azure, both AzureRM and AzAPI. The policy files are structured as follows:

## How to use it

To use these policies, you can use the [Conftest](https://www.conftest.dev/) tool. You can use the following command to run the policies against your Terraform plan:

```bash
conftest test --all-namespaces -p <path-to-policies>/policy <path-to-tfplan>
```

## Supported Policies

### [Azure-Proactive-Resiliency-Library-v2](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/)

#### `Microsoft.ContainerService/managedClusters`
[`configure_aks_default_node_pool_zones`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/ContainerService/managedClusters/#deploy-aks-cluster-across-availability-zones)
#### `Microsoft.DocumentDB/databaseAccounts`
[`configure_cosmosdb_account_continuous_backup_mode`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DocumentDB/databaseAccounts/#configure-continuous-backup-mode)
#### `Microsoft.Network/applicationGateways`
[`migrate_to_application_gateway_v2`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/applicationGateways/#migrate-to-application-gateway-v2)
[`deploy_application_gateway_in_a_zone_redundant_configuration`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/applicationGateways/#deploy-application-gateway-in-a-zone-redundant-configuration)
#### `Microsoft.Network/loadBalancers`
[`use_nat_gateway_instead_of_outbound_rules_for_production_load_lalancer`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/loadBalancers/#use-nat-gateway-instead-of-outbound-rules-for-production-workloads)
[`use_resilient_load_lalancer_sku`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/loadBalancers/#use-standard-load-balancer-sku)
#### `Microsoft.DBforMySQL/flexibleServers`
[`mysql_flexible_server_high_availability_zone_redundant`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DBforMySQL/flexibleServers/#enable-ha-with-zone-redundancy)
[`mysql_flexible_server_geo_redundant_backup_enabled`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DBforMySQL/flexibleServers/#configure-geo-redundant-backup-storage)

## Apply(skip) policies

To apply a subset of policies, you can specify the policy folders you want to apply, e.g.:

```Bash
conftest test --all-namespaces -p <path-to-policies>/policy/Azure-Proactive-Resiliency-Library-v2 -p <path-to-policies>/policy/common <path-to-tfplan>
```

This will only apply the policies under `Azure-Proactive-Resiliency-Library-v2` and `common` folders. Please note that `policy/common` is required.

To skip a subset of policies, you can create an exception rego file, e.g.:

```rego
exception[rules] {
  rules = ["use_nat_gateway_instead_of_outbound_rules_for_production_load_lalancer"]
}
```

Save it to `exception.rego`, then you can apply the exception file with the policies:

```Bash
conftest test --all-namespaces -p exception.rego -p <path-to-policies>/policy <path-to-tfplan>
```

## Contribution

All contribution are welcome, please follow the structure below:

```text
.
├── common
├── ruleset1
│       ├── provider1
│       └── provider2
└── ruleset2
    ├── provider1
    └── provider2
```

The policy files are grouped by ruleset, then provider. Now `azurerm` policies should be further grouped by service folder as [`terraform-provider-azurerm`](https://github.com/hashicorp/terraform-provider-azurerm/tree/main/internal/services).

All shared util code **MUST** be stored in `common` folder.

Each rego file **MUST** has a corresponding `xxx.mock.json` file. The mock JSON file should contain a top-level key named "mock", which maps to a dictionary. This dictionary can have keys "valid" and "invalid", each mapping to another dictionary of test cases.

Example structure for mock JSON files:

```json
{
  "mock": {
    "valid": {
      "case1": {...},
      "case2": {...}
    },
    "invalid": {
      "case1": {...},
      "case2": {...}
    }
  }
}
```

Alternatively, you can put all cases under the `mock` key directly:

```json
{
  "mock": {
    "case1": {...},
    "invalid_case2": {...}
  }
}
```

Any keys other than `valid` and `invalid` would be treated as a single case, any single cases without invalid prefix would be considered as a valid case.

To contribute a new policy, you **MUST** provide at least one valid case.

## Use unique rule name as `deny` function name

Please do:

```rego
deny_migrate_to_application_gateway_v2[reason] {
    tfplan := data.utils.tfplan(input)
    resource := tfplan.resource_changes[_]
    resource.mode == "managed"
    resource.type == "azapi_resource"
    data.utils.is_create_or_update(resource.change.actions)
    data.utils.is_azure_type(resource.change.after, "Microsoft.Network/applicationGateways")
    not valid_sku(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2: '%s' `azapi_resource` must have 'body.properties.sku.name' set to 'Standard_v2' or 'WAF_v2': https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/applicationGateways/#migrate-to-application-gateway-v2", [resource.address])
}
```

Please **DO NOT**:

```rego
deny[reason] {
    tfplan := data.utils.tfplan(input)
    resource := tfplan.resource_changes[_]
    resource.mode == "managed"
    resource.type == "azapi_resource"
    data.utils.is_create_or_update(resource.change.actions)
    data.utils.is_azure_type(resource.change.after, "Microsoft.Network/applicationGateways")
    not valid_sku(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2: '%s' `azapi_resource` must have 'body.properties.sku.name' set to 'Standard_v2' or 'WAF_v2': https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/applicationGateways/#migrate-to-application-gateway-v2", [resource.address])
}
```

These rule names could be used in [`exceptions`](https://www.conftest.dev/exceptions/) so users could skip the check for specific resources.

## Do not use `input` directly in your policy

According to the [HashiCorp's OPA policies document](https://github.com/aws-samples/aws-infra-policy-as-code-with-terraform):

>The run data contains information like workspace details and the organization name. To access the properties from the Terraform plan data in your policies, use `input.plan`. To access properties from the Terraform run, use `input.run`.

Unlike Terraform plan file, the actual plan on HCP Terraform are wrapped in `input.plan`, so you **MUST** use `tfplan := data.utils.tfplan(input)` to get the actual plan object.

## Don't forget to update the README

Please update the README file to include the new policy in [#Supported Policies](#supported-policies) section.