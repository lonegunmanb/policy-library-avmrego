package checkov

import rego.v1

valid_azurerm_vm_no_creds_in_custom_data(resource) if {
    not string_has_secrets(resource.values.os_profile[0].custom_data[0])
}

deny_CKV_AZURE_45 contains reason if {
    resource := data.utils.resource(input, "azurerm_virtual_machine")[_]
    resource.values.os_profile
    resource.values.os_profile[_].custom_data
    resource.values.os_profile[_].custom_data[_]
    not valid_azurerm_vm_no_creds_in_custom_data(resource)

    reason := sprintf("checkov/CKV_AZURE_45: Ensure that no sensitive credentials are exposed in VM custom_data. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/VMCredsInCustomData.py")
}

string_has_secrets(str) if {

    patterns := [
        "(?i)(password)",
        "(?i)(access_key)",
        "(?i)(secret)",
        "(?i)(token)",
        "(?i)(credentials)",
        "(?i)(private_key)",
        "(?i)(ssh_key)",
    ]

    rego.v1.re_match(patterns[_], str)
}