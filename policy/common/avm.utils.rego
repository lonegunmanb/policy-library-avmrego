package utils

tfplan(d) = output {
    d.plan.resource_changes
    output := d.plan
}

tfplan(d) = output {
    not d.plan.resource_changes
    output := d
}