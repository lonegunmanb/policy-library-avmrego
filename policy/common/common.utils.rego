package utils

# Checks if action is create or update
# Common path: resource.change.actions
is_create_or_update(change_actions) if {
	change_actions[count(change_actions) - 1] == "create"
}

is_create_or_update(change_actions) if {
	change_actions[count(change_actions) - 1] == "update"
}

is_resource_create_or_update(resource) if {
	is_create_or_update(resource.change.actions)
}