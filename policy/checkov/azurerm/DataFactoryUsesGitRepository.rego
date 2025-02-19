package checkov

import rego.v1

valid_azurerm_data_factory_uses_git(resource) if {
  resource.values.github_configuration[_].repository_name != null
}

valid_azurerm_data_factory_uses_git(resource) if {
  resource.values.vsts_configuration[_].repository_name != null
}

deny_CKV_AZURE_103 contains reason if {
  resource := data.utils.resource(input, "azurerm_data_factory")[_]
  not valid_azurerm_data_factory_uses_git(resource)

  reason := sprintf("checkov/CKV_AZURE_103: Ensure that Azure Data Factory uses Git repository for source control %s", [resource.address])
}
