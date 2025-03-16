/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// Grant defines a permission grant for a role
type Grant struct {
	// object_type, required
	ObjectType string `json:"object_type,omitempty"`
	// database, required
	// Database string `json:"database,omitempty"`
	// schema, default empty
	Schema string `json:"schema,omitempty"`
	// table, default empty
	Table string `json:"table,omitempty"`
	// columns, default empty
	// Columns []string `json:"columns,omitempty"`
	// objects, default empty
	Objects []string `json:"objects,omitempty"`
	// privileges, required
	Privileges []string `json:"privileges,omitempty"`
	// with_grant_option, default false
	// WithGrantOption bool `json:"with_grant_option,omitempty"`
}

// DatabaseConnection defines a database connection configuration
type DatabaseConnection struct {
	ConnectionString string `json:"connection_string,omitempty"`
}

type Role struct {
	// required
	Name string `json:"name"`
	// description, default empty
	Description string `json:"description,omitempty"`
	// can role login or can not, default true
	Login bool `json:"login,omitempty"`
	// should password be generated for user, default false
	// PasswordEnabled bool `json:"password_enabled,omitempty"`
	// can role initiate replication, default false
	Replication bool `json:"replication,omitempty"`
	// can role create databases, default false
	// CreateDatabase bool `json:"create_database,omitempty"`
	// can role create other roles, default false
	// CreateRole bool `json:"create_role,omitempty"`
	// list of roles where user is member, default empty
	MemberOf []string `json:"member_of,omitempty"`
	// list of users that are members of role, default empty
	Users []string `json:"users,omitempty"`
	// list of grants for role, default empty
	Grants []Grant `json:"grants,omitempty"`
}

// RolesSpec defines the desired state of Roles
type RolesSpec struct {
	// Important: Run "make" to regenerate code after modifying this file

	// +operator-sdk:csv:customresourcedefinitions:type=spec
	Database DatabaseConnection `json:"database,omitempty"`

	// +operator-sdk:csv:customresourcedefinitions:type=spec
	Roles []Role `json:"roles,omitempty"`
}

// RolesStatus defines the observed state of Roles
type RolesStatus struct {
	// Represents the observations of a Roles's current state.
	// Roles.status.conditions.type are: "Available", "Progressing", and "Degraded"
	// Roles.status.conditions.status are one of True, False, Unknown.
	// Roles.status.conditions.reason the value should be a CamelCase string and producers of specific
	// condition types may define expected values and meanings for this field, and whether the values
	// are considered a guaranteed API.
	// Roles.status.conditions.Message is a human readable message indicating details about the transition.
	// For further information see: https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties

	// Conditions store the status conditions of the Roles instances
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,1,rep,name=conditions"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// Roles is the Schema for the roles API
type Roles struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RolesSpec   `json:"spec,omitempty"`
	Status RolesStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RolesList contains a list of Roles
type RolesList struct {
	metav1.TypeMeta `        json:",inline"`
	metav1.ListMeta `        json:"metadata,omitempty"`
	Items           []Roles `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Roles{}, &RolesList{})
}
