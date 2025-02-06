package utils

is_create_or_update(change_actions) {
	change_actions[count(change_actions) - 1] == ["create", "update"][_]
}

is_resource_create_or_update(resource) {
	is_create_or_update(resource.change.actions)
}