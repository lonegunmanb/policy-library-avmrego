package checkov

import rego.v1

valid_azurerm_iothub_no_public_network_access(resource) if {
    resource.values.public_network_access_enabled == false
}

deny_iothub_no_public_network_access contains reason if {
    resource := data.utils.resource(input, "azurerm_iothub")[_]
    not valid_azurerm_iothub_no_public_network_access(resource)

    reason := sprintf("checkov/CKV_AZURE_108: Ensure that Azure IoT Hub disables public network access. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/IoTNoPublicNetworkAccess.py")
}
