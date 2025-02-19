package checkov

import rego.v1

valid_azurerm_redis_cache_enable_ssl(resource) if {
    resource.values.enable_non_ssl_port == false
}

deny_CKV_AZURE_91 contains reason if {
    resource := data.utils.resource(input, "azurerm_redis_cache")[_]
    not valid_azurerm_redis_cache_enable_ssl(resource)

    reason := sprintf("checkov/CKV_AZURE_91: Ensure that only SSL are enabled for Cache for Redis. Resource %s has non-ssl port enabled. https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/checks/resource/azure/RedisCacheEnableNonSSLPort.py", [resource.address])
}
