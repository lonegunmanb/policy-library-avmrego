package checkov

import rego.v1

valid_azurerm_monitor_log_profile_categories(resource) if {
    categories := ["Write", "Delete", "Action"]
    res_categories := resource.values.categories

    is_list := is_list(res_categories)
    not is_empty := count(res_categories) > 0

    is_list
    not_is_empty
    all(categories, function(category) {
        contains(res_categories[_], category)
    })
}

deny_monitor_log_profile_captures_all_activities contains reason if {
    resource := data.utils.resource(input, "azurerm_monitor_log_profile")[_]
    not valid_azurerm_monitor_log_profile_categories(resource)

    reason := sprintf("checkov/CKV_AZURE_38: Ensure audit profile captures all the activities. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/MonitorLogProfileCategories.py")
}

is_list(x) = true {
  typeof(x) == "array"
}

is_list(x) = false {
  true
}
