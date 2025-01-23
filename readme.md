# Azure Rego Policies

This repository contains some [Rego](https://www.openpolicyagent.org/) policy files designed for Azure, both AzureRM and AzAPI. The policy files are structured as follows:

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

## Do not use `input` directly in your policy

According to the [HashiCorp's OPA policies document](https://github.com/aws-samples/aws-infra-policy-as-code-with-terraform):

>The run data contains information like workspace details and the organization name. To access the properties from the Terraform plan data in your policies, use `input.plan`. To access properties from the Terraform run, use `input.run`.

Unlike Terraform plan file, the actual plan on HCP Terraform are wrapped in `input.plan`, so you **MUST** use `tfplan := data.utils.tfplan(input)` to get the actual plan object.

## Special thanks

This repository uses [a common utils library provided by `aws-infra-policy-as-code-with-terraform`](https://github.com/aws-samples/aws-infra-policy-as-code-with-terraform), thanks a lot!