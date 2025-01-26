package utils

tfplan(d) = output {
    d.plan.resource_changes
    output := d.plan
}

tfplan(d) = output {
    not d.plan.resource_changes
    output := d
}

is_azure_type(resource, azure_type) {
    regex.match(sprintf("^%s@", [azure_type]), resource.type)
}