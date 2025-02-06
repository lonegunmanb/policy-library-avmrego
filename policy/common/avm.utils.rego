package utils

tfplan(d) = output if {
    d.plan.resource_changes
    output := d.plan
}

tfplan(d) = output if {
    not d.plan.resource_changes
    output := d
}

is_azure_type(resource, azure_type) if {
    regex.match(sprintf("^%s@", [azure_type]), resource.type)
}