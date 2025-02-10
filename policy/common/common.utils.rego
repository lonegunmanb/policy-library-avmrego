package utils

import rego.v1

is_azure_type(resource, azure_type) if {
	regex.match(sprintf("^%s@", [azure_type]), resource.type)
}

_resource(_input) := output if {
	_input.plan.resource_changes == _input.plan.resource_changes
	output := {
	body |
		r := _input.plan.resource_changes[_]
		body := {
			"address": r.address,
			"values": r.change.after,
			"mode": r.mode,
			"type": r.type,
		}
	}
}

_resource(_input) := output if {
	_input.resource_changes == _input.resource_changes
	output := {
	body |
		r := _input.resource_changes[_]
		body := {
			"address": r.address,
			"values": r.change.after,
			"mode": r.mode,
			"type": r.type,
		}
	}
}

_resource(_input) := output if {
	_input.values.root_module.resources == _input.values.root_module.resources
	output := {
	body |
		r := _input.values.root_module.resources[_]
		body := {
			"address": r.address,
			"values": r.values,
			"mode": r.mode,
			"type": r.type,
		}
	}
}

resource(_input, resource_type) := {
resource |
	some resource in _resource(_input)
	resource.mode == "managed"
	resource.type == resource_type
}

is_create_or_update(change_actions) if {
	change_actions[count(change_actions) - 1] == ["create", "update"][_]
}

is_resource_create_or_update(resource) if {
	is_create_or_update(resource.change.actions)
}
