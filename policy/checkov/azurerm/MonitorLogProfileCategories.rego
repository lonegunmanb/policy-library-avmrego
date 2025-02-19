package checkov

import rego.v1

valid_azurerm_monitor_log_profile_categories(resource) if {
    categories := ["Write", "Delete", "Action"]
    res_categories := resource.values.categories
    is_list(res_categories)
    count(res_categories) > 0
    all_categories_present := true
    
    # Iterate through the required categories and check if they are present in the resource
    # Assumes res_categories is a list of lists
    
    every i, category in categories {
        contains(res_categories[0], category)
    }


}

deny_CKV_AZURE_38 contains reason if {
    resource := data.utils.resource(input, "azurerm_monitor_log_profile")[_]
    not valid_azurerm_monitor_log_profile_categories(resource)
    reason := sprintf("checkov/CKV_AZURE_38: Ensure audit profile captures all the activities. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/MonitorLogProfileCategories.py")
}
