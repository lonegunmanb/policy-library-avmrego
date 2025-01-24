package utils

tfplan(d) = output {
    d.plan.resource_changes
    output := d.plan
}

tfplan(d) = output {
    not d.plan.resource_changes
    output := d
}

azapi_resource_type_equals(resource, type) {
    regex.match(sprintf(`^%s@`, type), resource.type)
} else = false {
 	true
}