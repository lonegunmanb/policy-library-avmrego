# Azure Rego Policies

This repository contains some [Rego](https://www.openpolicyagent.org/) policy files designed for Azure, both AzureRM and AzAPI. The policy files are structured as follows:

## How to use it

To use these policies, you can use the [Conftest](https://www.conftest.dev/) tool. You can use the following command to run the policies against your Terraform plan:

```bash
conftest test --all-namespaces --update git::https://github.com/lonegunmanb/policy-library-avmrego.git//policy <path-to-tfplan>
```

To generate a Terraform plan file:

```bash
terraform plan -out=tfplan.binary && terraform show -json tfplan.binary > tfplan.json
```

Or you can use this library against the brown field infrastructure:

```bash
terraform show -json > state.json
conftest test --all-namespaces --update git::https://github.com/lonegunmanb/policy-library-avmrego.git//policy state.json
```

## Supported Policies

### [Azure-Proactive-Resiliency-Library-v2](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/)

* `Microsoft.Compute/virtualMachines`

[`mission_critical_virtual_machine_should_use_premium_or_ultra_disks`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Compute/virtualMachines/#mission-critical-workloads-should-consider-using-premium-or-ultra-disks)
`legacy_virtual_machine_not_allowed`

* `Microsoft.ContainerService/managedClusters`

[`configure_aks_default_node_pool_zones`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/ContainerService/managedClusters/#deploy-aks-cluster-across-availability-zones)

* `Microsoft.DocumentDB/databaseAccounts`

[`configure_cosmosdb_account_continuous_backup_mode`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DocumentDB/databaseAccounts/#configure-continuous-backup-mode)

* `Microsoft.Network/applicationGateways`

[`migrate_to_application_gateway_v2`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/applicationGateways/#migrate-to-application-gateway-v2)
[`deploy_application_gateway_in_a_zone_redundant_configuration`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/applicationGateways/#deploy-application-gateway-in-a-zone-redundant-configuration)

* `Microsoft.Network/loadBalancers`

[`use_nat_gateway_instead_of_outbound_rules_for_production_load_lalancer`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/loadBalancers/#use-nat-gateway-instead-of-outbound-rules-for-production-workloads)
[`use_resilient_load_lalancer_sku`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/loadBalancers/#use-standard-load-balancer-sku)

* `Microsoft.Network/publicIPAddresses`

[`public_ip_use_standard_sku_and_zone_redundant_ip`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/publicIPAddresses/#use-standard-sku-and-zone-redundant-ips-when-applicable)

* `Microsoft.Network/virtualNetworkGateways`

[`virtual_network_gateway_use_zone_redundant_sku`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/virtualNetworkGateways/#use-zone-redundant-expressroute-gateway-skus)

* `Microsoft.DBforMySQL/flexibleServers`

[`mysql_flexible_server_high_availability_mode_zone_redundant`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DBforMySQL/flexibleServers/#enable-ha-with-zone-redundancy)
[`mysql_flexible_server_geo_redundant_backup_enabled`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DBforMySQL/flexibleServers/#configure-geo-redundant-backup-storage)

* `Microsoft.DBforPostgreSQL/flexibleServers`

[`postgresql_flexible_server_high_availability_mode_zone_redundant`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DBforPostgreSQL/flexibleServers/#enable-ha-with-zone-redundancy)

* `Microsoft.Storage/storageAccounts`

[`storage_accounts_are_zone_or_region_redundant`](https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Storage/storageAccounts/#ensure-that-storage-accounts-are-zone-or-region-redundant)

## Apply(skip) policies

To apply a subset of policies, you can specify the policy folders you want to apply, e.g.:

```Bash
conftest test --all-namespaces -p <path-to-policies>/policy/Azure-Proactive-Resiliency-Library-v2 -p <path-to-policies>/policy/common <path-to-tfplan>
```

This will only apply the policies under `Azure-Proactive-Resiliency-Library-v2` and `common` folders. Please note that `policy/common` is required.

To skip a subset of policies, you can create an exception rego file, e.g.:

```rego
package Azure_Proactive_Resiliency_Library_v2.use_nat_gateway_instead_of_outbound_rules_for_production_load_lalancer

import rego.v1

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

## Use unique rule name as `deny` rule name

Please do:

```rego
deny_migrate_to_application_gateway_v2 contains reason if {
    resource := data.utils.resource(input, "azurerm_application_gateway")[_]
    not valid_azurerm_sku(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2: '%s' `azurerm_application_gateway` must have 'sku.name' set to 'Standard_v2' or 'WAF_v2': https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/applicationGateways/#migrate-to-application-gateway-v2", [resource.address])
}
```

Please **DO NOT**:

```rego
deny contains reason if {
    resource := data.utils.resource(input, "azurerm_application_gateway")[_]
    not valid_azurerm_sku(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2: '%s' `azurerm_application_gateway` must have 'sku.name' set to 'Standard_v2' or 'WAF_v2': https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/Network/applicationGateways/#migrate-to-application-gateway-v2", [resource.address])
}
```

These rule names could be used in [`exceptions`](https://www.conftest.dev/exceptions/) so users could skip the check for specific resources.

## Use rule name as package name suffix

Please do:

```rego
package Azure_Proactive_Resiliency_Library_v2.configure_cosmosdb_account_continuous_backup_mode

import rego.v1

valid_azurerm_cosmosdb_account_backup_policy_type(resource) if {
    resource.values.backup[_].type == "Continuous"
}

deny_configure_cosmosdb_account_continuous_backup_mode contains reason if {
    resource := data.utils.resource(input, "azurerm_cosmosdb_account")[_]
    not valid_azurerm_cosmosdb_account_backup_policy_type(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2: '%s' `azurerm_cosmosdb_account` must have backup type configured to 'Continuous': https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DocumentDB/databaseAccounts/#configure-continuous-backup-mode", [resource.address])
}
```

Since we have rules for both `azurerm` and `azapi` providers, we need a predictable way to add a rule into exception list. Assuming we have the same rule for `azapi` resource:

```rego
package Azure_Proactive_Resiliency_Library_v2.configure_cosmosdb_account_continuous_backup_mode

import rego.v1

valid_azapi_cosmosdb_account_backup_policy_type(resource) if {
    resource.values.body.properties.backupPolicy.type == "Continuous"
}

deny_configure_cosmosdb_account_continuous_backup_mode contains reason if {
    resource := data.utils.resource(input, "azapi_resource")[_]
    data.utils.is_azure_type(resource.values, "Microsoft.DocumentDB/databaseAccounts")
    not valid_azapi_cosmosdb_account_backup_policy_type(resource)

    reason := sprintf("Azure-Proactive-Resiliency-Library-v2: '%s' `azapi_resource` must have backup type configured to 'Continuous': https://azure.github.io/Azure-Proactive-Resiliency-Library-v2/azure-resources/DocumentDB/databaseAccounts/#configure-continuous-backup-mode", [resource.address])
}
```

To ignore rule `configure_cosmosdb_account_continuous_backup_mode`, we need a new rego file:

```Rego
package Azure_Proactive_Resiliency_Library_v2.configure_cosmosdb_account_continuous_backup_mode

import rego.v1

exception contains rules if {
    rules = ["configure_cosmosdb_account_continuous_backup_mode"]
}
```

## Make your helper function name unique

As we are using rule name as package name suffix, we need to make sure the helper function name is unique. Please use the helper function name unique, the provider name could help here:

```rego
valid_azapi_cosmosdb_account_backup_policy_type(resource) if {
    resource.values.body.properties.backupPolicy.type == "Continuous"
}
```

## Do not use `input` directly in your policy

According to the [HashiCorp's OPA policies document](https://github.com/aws-samples/aws-infra-policy-as-code-with-terraform):

>The run data contains information like workspace details and the organization name. To access the properties from the Terraform plan data in your policies, use `input.plan`. To access properties from the Terraform run, use `input.run`.

Unlike Terraform plan file, the actual plan on HCP Terraform are wrapped in `input.plan`, so you **MUST** use `resource := data.utils.resource(input, "azurerm_postgresql_flexible_server")[_]` to get the actual plan object.

## Don't forget to update the README

Please update the README file to include the new policy in [#Supported Policies](#supported-policies) section.