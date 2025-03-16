# PSQL Roles Operator

Kubernetes Operator that manages PostgreSQL roles and users.

## Description

PostgreSQL Roles Operator can:

1. Create roles with optional description, login, replication.
1. Drop roles if they dissapear from the Roles custom resource.
1. Reconcile roles spec.
1. Reconcile role grants, memberships.
1. Reconcile additional users with login=true that belong to the role.

More to come!

**Note:** This operator is not production ready yet. It is under active development.

## Usage

1. Install operator
   ```bash
   kubectl apply -f https://raw.githubusercontent.com/rgeraskin/psql-roles-operator/v0.0.1/dist/install.yaml
   ```
1. Create Roles custom resource
   ```yaml
   apiVersion: postgresql.rgeraskin.dev/v1alpha1
   kind: Roles
   metadata:
     name: roles
   spec:
     database:
       connection_string: postgres://postgres:password@localhost:15432/postgres?sslmode=disable
     roles:
       - name: test_role
         description: test role # optional
         login: true # optional, default false
         replication: false # optional, default false
         grants: # optional, default empty so removes all grants
           - schema: public
             object_type: table
             objects:
               - table1
               - table2
             privileges:
               - insert
               - SELECT
         member_of: # optional, default empty
           - parent_role1
           - parent_role2
         users: # optional, default empty. Creates users with login=true and memberOf=<this role>
           - user1
           - user2
    ```
### Limitations

Will be fixed in future releases:

1. Roles password is not created by operator.
1. Only object_type=table is supported for grants.
1. CreateDatabase and CreateRole permissions are not supported.
1. If role is an owner of some object, it will not be deleted.
1. Weak schema validation.

## Development

### Prerequisites
- go version v1.22.0+
- docker version 17.03+.
- kubectl version v1.11.3+.
- Access to a Kubernetes v1.11.3+ cluster.

### To Deploy on the cluster
**Build and push your image to the location specified by `IMG`:**

```sh
make docker-build docker-push IMG=<some-registry>/psql-roles-operator:tag
```

**NOTE:** This image ought to be published in the personal registry you specified.
And it is required to have access to pull the image from the working environment.
Make sure you have the proper permission to the registry if the above commands don’t work.

**Install the CRDs into the cluster:**

```sh
make install
```

**Deploy the Manager to the cluster with the image specified by `IMG`:**

```sh
make deploy IMG=<some-registry>/psql-roles-operator:tag
```

> **NOTE**: If you encounter RBAC errors, you may need to grant yourself cluster-admin
privileges or be logged in as admin.

**Create instances of your solution**
You can apply the samples (examples) from the config/sample:

```sh
kubectl apply -k config/samples/
```

>**NOTE**: Ensure that the samples has default values to test it out.

### To Uninstall
**Delete the instances (CRs) from the cluster:**

```sh
kubectl delete -k config/samples/
```

**Delete the APIs(CRDs) from the cluster:**

```sh
make uninstall
```

**UnDeploy the controller from the cluster:**

```sh
make undeploy
```

## Project Distribution

Following are the steps to build the installer and distribute this project to users.

1. Build the installer for the image built and published in the registry:

```sh
make build-installer IMG=<some-registry>/psql-roles-operator:tag
```

NOTE: The makefile target mentioned above generates an 'install.yaml'
file in the dist directory. This file contains all the resources built
with Kustomize, which are necessary to install this project without
its dependencies.

2. Using the installer

Users can just run kubectl apply -f <URL for YAML BUNDLE> to install the project, i.e.:

```sh
kubectl apply -f https://raw.githubusercontent.com/<org>/psql-roles-operator/<tag or branch>/dist/install.yaml
```

## Contributing
// TODO(user): Add detailed information on how you would like others to contribute to this project

**NOTE:** Run `make help` for more information on all potential `make` targets

More information can be found via the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

## License

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

