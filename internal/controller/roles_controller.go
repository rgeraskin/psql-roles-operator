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

package controller

import (
	"context"
	"fmt"

	"go.uber.org/zap/zapcore"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/go-logr/logr"
	postgresqlv1alpha1 "github.com/rgeraskin/psql-roles-operator/api/v1alpha1"
	"github.com/rgeraskin/psql-roles-operator/internal/postgres"
)

const rolesFinalizer = "postgresql.rgeraskin.dev/finalizer"

// Definitions to manage status conditions
// const (
// )

// RolesReconciler reconciles a Roles object
type RolesReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
	logger   logr.Logger
}

func NewRolesReconciler(
	client client.Client,
	scheme *runtime.Scheme,
	recorder record.EventRecorder,
) *RolesReconciler {
	opts := zap.Options{}
	opts.Development = true
	opts.EncoderConfigOptions = []zap.EncoderConfigOption{
		func(config *zapcore.EncoderConfig) {
			config.EncodeLevel = zapcore.CapitalColorLevelEncoder
		},
	}
	logger := zap.New(zap.UseFlagOptions(&opts)).WithName("reconcile")

	return &RolesReconciler{
		Client:   client,
		Scheme:   scheme,
		Recorder: recorder,
		logger:   logger,
	}
}

func (r *RolesReconciler) updateConditions(
	ctx *context.Context,
	req *ctrl.Request,
	roles *postgresqlv1alpha1.Roles,
	condition *metav1.Condition,
) error {
	r.logger.V(1).
		Info(
			"Update Roles Conditions",
			"type", condition.Type,
			"status", condition.Status,
			"reason", condition.Reason,
			"message", condition.Message,
		)
	meta.SetStatusCondition(&roles.Status.Conditions, *condition)

	if err := r.Status().Update(*ctx, roles); err != nil {
		return fmt.Errorf("failed to update Roles Conditions: %w", err)
	}

	// Let's re-fetch the Roles Custom Resource after updating the status
	// so that we have the latest state of the resource on the cluster and we will avoid
	// raising the error "the object has been modified, please apply
	// your changes to the latest version and try again" which would re-trigger the reconciliation
	// if we try to update it again in the following operations
	if err := r.Get(*ctx, req.NamespacedName, roles); err != nil {
		return fmt.Errorf("failed to re-fetch roles: %w", err)
	}

	return nil
}

// The following markers are used to generate the rules permissions (RBAC) on config/rbac using controller-gen
// when the command <make manifests> is executed.
// To know more about markers see: https://book.kubebuilder.io/reference/markers.html

// +kubebuilder:rbac:groups=postgresql.rgeraskin.dev,resources=roles,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=postgresql.rgeraskin.dev,resources=roles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=postgresql.rgeraskin.dev,resources=roles/finalizers,verbs=update
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// It is essential for the controller's reconciliation loop to be idempotent. By following the Operator
// pattern you will create Controllers which provide a reconcile function
// responsible for synchronizing resources until the desired state is reached on the cluster.
// Breaking this recommendation goes against the design principles of controller-runtime.
// and may lead to unforeseen consequences such as resources becoming stuck and requiring manual intervention.
// For further info:
// - About Operator Pattern: https://kubernetes.io/docs/concepts/extend-kubernetes/operator/
// - About Controllers: https://kubernetes.io/docs/concepts/architecture/controller/
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/reconcile
func (r *RolesReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// r.logger = log.FromContext(ctx).WithName("reconcile").WithValues()

	// Fetch the Roles instance
	// The purpose is check if the Custom Resource for the Kind Roles
	// is applied on the cluster if not we return nil to stop the reconciliation
	r.logger.V(1).Info("Fetch the Roles instance")
	roles := &postgresqlv1alpha1.Roles{}
	err := r.Get(ctx, req.NamespacedName, roles)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// If the custom resource is not found then it usually means that it was deleted or not created
			// In this way, we will stop the reconciliation
			r.logger.Info("roles resource not found. Ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		r.logger.Error(err, "Failed to get Roles")
		return ctrl.Result{}, err
	}

	ConditionReady := metav1.Condition{
		Type: "Ready",
	}
	defer r.updateConditions(
		&ctx,
		&req,
		roles,
		&ConditionReady,
	)

	// Let's just set the status as Unknown when no status is available
	r.logger.V(1).Info("Check if the status is available")
	ConditionReady.Reason = "Initializing"
	if len(roles.Status.Conditions) == 0 {
		r.logger.V(1).Info("Status is empty, set it to Unknown")
		ConditionReady.Status = metav1.ConditionUnknown
		ConditionReady.Message = "No conditions are available"
	}

	// Let's add a finalizer. Then, we can define some operations which should
	// occur before the custom resource is deleted.
	// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/finalizers
	r.logger.V(1).Info("Check if the custom resource has a finalizer")
	if !controllerutil.ContainsFinalizer(roles, rolesFinalizer) {
		r.logger.Info("Adding Finalizer for Roles")
		if ok := controllerutil.AddFinalizer(roles, rolesFinalizer); !ok {
			r.logger.Error(nil, "Failed to add finalizer into the custom resource")
			ConditionReady.Status = metav1.ConditionFalse
			ConditionReady.Message = "Failed to add finalizer into the custom resource"
			// we don't have errors, so we don't need to requeue
			return ctrl.Result{Requeue: true}, nil
		}

		if err = r.Update(ctx, roles); err != nil {
			r.logger.Error(err, "Failed to update custom resource to add finalizer")
			ConditionReady.Status = metav1.ConditionFalse
			ConditionReady.Message = "Failed to update custom resource to add finalizer"
			return ctrl.Result{}, err
		}
	}

	// Create a new PostgreSQL client
	r.logger.V(1).Info("Create a new PostgreSQL client")
	pgClient, err := postgres.NewClient(ctx, roles.Spec.Database.ConnectionString)
	if err != nil {
		r.logger.Error(err, "Failed to create PostgreSQL client")
		ConditionReady.Status = metav1.ConditionFalse
		ConditionReady.Message = "Failed to create PostgreSQL client"
		return ctrl.Result{}, err
	}
	defer pgClient.Close()

	// Check if the Roles instance is marked to be deleted, which is
	// indicated by the deletion timestamp being set.
	r.logger.V(1).Info("Check if the Roles instance is marked to be deleted")
	isRolesMarkedToBeDeleted := roles.GetDeletionTimestamp() != nil
	if isRolesMarkedToBeDeleted {
		if controllerutil.ContainsFinalizer(roles, rolesFinalizer) {
			r.logger.Info("Performing Finalizer Operations for Roles before delete CR")

			// Let's set here a status to reflect that this resource began its process to be terminated.
			ConditionReady.Status = metav1.ConditionFalse
			ConditionReady.Reason = "Finalizing"
			ConditionReady.Message = "Performing finalizer operations"

			// Delete all roles from PostgreSQL
			for _, role := range roles.Spec.Roles {
				if err := pgClient.DropRole(role.Name); err != nil {
					r.logger.Error(err, "Failed to drop role", "role", role.Name)
					ConditionReady.Message = "Failed to drop role"
					return ctrl.Result{}, err
				}
			}

			r.logger.Info("Removing Finalizer for Roles after successfully perform the operations")
			if ok := controllerutil.RemoveFinalizer(roles, rolesFinalizer); !ok {
				r.logger.Error(nil, "Failed to remove finalizer for Roles")
				ConditionReady.Message = "Failed to remove finalizer from the custom resource"
				// we don't have errors, so we don't need to requeue
				return ctrl.Result{Requeue: true}, nil
			}

			if err := r.Update(ctx, roles); err != nil {
				r.logger.Error(err, "Failed to remove finalizer for Roles")
				ConditionReady.Message = "Failed to update custom resource to remove finalizer"
				return ctrl.Result{}, err
			}

			ConditionReady.Status = metav1.ConditionTrue
			ConditionReady.Message = "Finalizer operations successfully done"
		}
		return ctrl.Result{}, nil
	}

	// Get the previous version of the resource
	r.logger.V(1).Info("Get the previous version of the resource")
	previousRoles := &postgresqlv1alpha1.Roles{}
	err = r.Get(ctx, req.NamespacedName, previousRoles)
	if err != nil && !apierrors.IsNotFound(err) {
		r.logger.Error(err, "Failed to get previous version of roles")
		ConditionReady.Status = metav1.ConditionFalse
		ConditionReady.Message = "Failed to get previous version of roles"
		return ctrl.Result{}, err
	}

	// Create maps of role names for comparison
	r.logger.V(1).Info("Create maps of role names for comparison")
	currentRoles := make(map[string]bool)
	previousRolesMap := make(map[string]bool)

	for _, role := range roles.Spec.Roles {
		currentRoles[role.Name] = true
	}

	for _, role := range previousRoles.Spec.Roles {
		previousRolesMap[role.Name] = true
	}

	// Find roles that were removed
	r.logger.V(1).Info("Find roles that were removed")
	rolesToDrop := []string{}
	for roleName := range previousRolesMap {
		if !currentRoles[roleName] {
			r.logger.Info("Role removed from spec", "role", roleName)
			rolesToDrop = append(rolesToDrop, roleName)
		}
	}

	// Reconcile roles
	r.logger.V(1).Info("Reconcile roles")
	ConditionReady.Reason = "Reconciling"
	if len(rolesToDrop) > 0 {
		r.logger.Info("Dropping removed roles", "roles", rolesToDrop)
		ConditionReady.Status = metav1.ConditionFalse
		for _, roleName := range rolesToDrop {
			if err := pgClient.DropRole(roleName); err != nil {
				r.logger.Error(err, "Failed to drop removed role", "role", roleName)
				ConditionReady.Message = fmt.Sprintf("Failed to drop removed role: %s", roleName)
				return ctrl.Result{}, err
			}
		}

		ConditionReady.Status = metav1.ConditionTrue
		ConditionReady.Message = "Successfully dropped removed roles"
	}

	ConditionReady.Status = metav1.ConditionFalse
	ConditionReady.Message = "Reconcile roles"
	err = nil
	for _, role := range roles.Spec.Roles {
		// Create role
		r.logger.V(1).Info(
			"Create or update role",
			"roleName", role.Name,
			"roleDescription", role.Description,
			"roleLogin", role.Login,
			"roleReplication", role.Replication,
			"roleMemberOf", role.MemberOf,
			"roleUsers", role.Users,
			"roleGrants", role.Grants,
		)

		err = pgClient.CreateRole(&role)

		if err != nil && err.Error() != fmt.Sprintf("pq: role \"%s\" already exists", role.Name) {
			r.logger.Error(err, "Failed to create role", "roleName", role.Name)
			ConditionReady.Message = fmt.Sprintf("Failed to create role: %s", role.Name)
			break
		}

		// If the role already exists, we should update the role
		if err != nil && err.Error() == fmt.Sprintf("pq: role \"%s\" already exists", role.Name) {
			r.logger.Info("Role already exists, should update it", "roleName", role.Name)

			// description
			r.logger.V(1).
				Info("Set role description", "roleName", role.Name, "description", role.Description)
			err = pgClient.SetRoleDescription(role.Name, role.Description)
			if err != nil {
				r.logger.Error(
					err,
					"Failed to set role description",
					"roleName",
					role.Name,
					"description",
					role.Description,
				)
				ConditionReady.Message = fmt.Sprintf(
					"Failed to reconcile role description: %s",
					role.Name,
				)
				break
			}

			// login
			r.logger.V(1).Info("Set role login", "roleName", role.Name, "login", role.Login)
			err = pgClient.SetRoleLogin(role.Name, role.Login)
			if err != nil {
				r.logger.Error(
					err,
					"Failed to set role login",
					"roleName",
					role.Name,
					"login",
					role.Login,
				)
				ConditionReady.Message = fmt.Sprintf(
					"Failed to reconcile role login: %s",
					role.Name,
				)
				break
			}

			// replication
			r.logger.V(1).
				Info("Set role replication", "roleName", role.Name, "replication", role.Replication)
			err = pgClient.SetRoleReplication(role.Name, role.Replication)
			if err != nil {
				r.logger.Error(
					err,
					"Failed to set role replication",
					"roleName",
					role.Name,
					"replication",
					role.Replication,
				)
				ConditionReady.Message = fmt.Sprintf(
					"Failed to reconcile role replication: %s",
					role.Name,
				)
				break
			}

			// memberOf
			r.logger.V(1).
				Info("Set role member of", "roleName", role.Name, "memberOf", role.MemberOf)
			err = pgClient.SetRoleMemberOf(role.Name, role.MemberOf)
			if err != nil {
				r.logger.Error(
					err,
					"Failed to set role member of",
					"roleName",
					role.Name,
					"memberOf",
					role.MemberOf,
				)
				ConditionReady.Message = fmt.Sprintf(
					"Failed to reconcile role member_of: %s",
					role.Name,
				)
				break
			}

			// users
			r.logger.V(1).Info("Set role users", "roleName", role.Name, "users", role.Users)
			err = pgClient.SetRoleUsers(role.Name, role.Users)
			if err != nil {
				r.logger.Error(
					err,
					"Failed to set role users",
					"roleName",
					role.Name,
					"users",
					role.Users,
				)
				ConditionReady.Message = fmt.Sprintf(
					"Failed to reconcile role users: %s",
					role.Name,
				)
				break
			}

			// grants
			r.logger.V(1).Info("Set role grants", "roleName", role.Name, "grants", role.Grants)
			err = pgClient.SetRoleGrants(role.Name, role.Grants)
			if err != nil {
				r.logger.Error(
					err,
					"Failed to set role grants",
					"roleName",
					role.Name,
					"grants",
					role.Grants,
				)
				ConditionReady.Message = fmt.Sprintf(
					"Failed to reconcile role grants: %s",
					role.Name,
				)
				break
			}
		}
	}

	if err != nil {
		r.logger.Error(err, ConditionReady.Message)
		return ctrl.Result{}, err
	}

	// ok
	ConditionReady.Status = metav1.ConditionTrue
	ConditionReady.Message = "Successfully reconciled"
	return ctrl.Result{}, nil
}

// // finalizeMemcached will perform the required operations before delete the CR.
// func (r *RolesReconciler) doFinalizerOperationsForRoles(cr *postgresqlv1alpha1.Roles) {
// 	// TODO(user): Add the cleanup steps that the operator
// 	// needs to do before the CR can be deleted. Examples
// 	// of finalizers include performing backups and deleting
// 	// resources that are not owned by this CR, like a PVC.

// 	// Note: It is not recommended to use finalizers with the purpose of deleting resources which are
// 	// created and managed in the reconciliation. These ones, such as the Deployment created on this reconcile,
// 	// are defined as dependent of the custom resource. See that we use the method ctrl.SetControllerReference.
// 	// to set the ownerRef which means that the Deployment will be deleted by the Kubernetes API.
// 	// More info: https://kubernetes.io/docs/tasks/administer-cluster/use-cascading-deletion/

// 	// The following implementation will raise an event
// 	r.Recorder.Event(cr, "Warning", "Deleting",
// 		fmt.Sprintf("Custom Resource %s is being deleted from the namespace %s",
// 			cr.Name,
// 			cr.Namespace))
// }

// deploymentForMemcached returns a Memcached Deployment object
// func (r *MemcachedReconciler) deploymentForMemcached(
// 	memcached *cachev1alpha1.Memcached) (*appsv1.Deployment, error) {
// 	ls := labelsForMemcached(memcached.Name)
// 	replicas := memcached.Spec.Size

// 	// Get the Operand image
// 	image, err := imageForMemcached()
// 	if err != nil {
// 		return nil, err
// 	}

// 	dep := &appsv1.Deployment{
// 		ObjectMeta: metav1.ObjectMeta{
// 			Name:      memcached.Name,
// 			Namespace: memcached.Namespace,
// 		},
// 		Spec: appsv1.DeploymentSpec{
// 			Replicas: &replicas,
// 			Selector: &metav1.LabelSelector{
// 				MatchLabels: ls,
// 			},
// 			Template: corev1.PodTemplateSpec{
// 				ObjectMeta: metav1.ObjectMeta{
// 					Labels: ls,
// 				},
// 				Spec: corev1.PodSpec{
// 					// TODO(user): Uncomment the following code to configure the nodeAffinity expression
// 					// according to the platforms which are supported by your solution. It is considered
// 					// best practice to support multiple architectures. build your manager image using the
// 					// makefile target docker-buildx. Also, you can use docker manifest inspect <image>
// 					// to check what are the platforms supported.
// 					// More info: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#node-affinity
// 					//Affinity: &corev1.Affinity{
// 					//	NodeAffinity: &corev1.NodeAffinity{
// 					//		RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
// 					//			NodeSelectorTerms: []corev1.NodeSelectorTerm{
// 					//				{
// 					//					MatchExpressions: []corev1.NodeSelectorRequirement{
// 					//						{
// 					//							Key:      "kubernetes.io/arch",
// 					//							Operator: "In",
// 					//							Values:   []string{"amd64", "arm64", "ppc64le", "s390x"},
// 					//						},
// 					//						{
// 					//							Key:      "kubernetes.io/os",
// 					//							Operator: "In",
// 					//							Values:   []string{"linux"},
// 					//						},
// 					//					},
// 					//				},
// 					//			},
// 					//		},
// 					//	},
// 					//},
// 					SecurityContext: &corev1.PodSecurityContext{
// 						RunAsNonRoot: &[]bool{true}[0],
// 						// IMPORTANT: seccomProfile was introduced with Kubernetes 1.19
// 						// If you are looking for to produce solutions to be supported
// 						// on lower versions you must remove this option.
// 						SeccompProfile: &corev1.SeccompProfile{
// 							Type: corev1.SeccompProfileTypeRuntimeDefault,
// 						},
// 					},
// 					Containers: []corev1.Container{{
// 						Image:           image,
// 						Name:            "memcached",
// 						ImagePullPolicy: corev1.PullIfNotPresent,
// 						// Ensure restrictive context for the container
// 						// More info: https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted
// 						SecurityContext: &corev1.SecurityContext{
// 							// WARNING: Ensure that the image used defines an UserID in the Dockerfile
// 							// otherwise the Pod will not run and will fail with "container has runAsNonRoot and image has non-numeric user"".
// 							// If you want your workloads admitted in namespaces enforced with the restricted mode in OpenShift/OKD vendors
// 							// then, you MUST ensure that the Dockerfile defines a User ID OR you MUST leave the "RunAsNonRoot" and
// 							// "RunAsUser" fields empty.
// 							RunAsNonRoot: &[]bool{true}[0],
// 							// The memcached image does not use a non-zero numeric user as the default user.
// 							// Due to RunAsNonRoot field being set to true, we need to force the user in the
// 							// container to a non-zero numeric user. We do this using the RunAsUser field.
// 							// However, if you are looking to provide solution for K8s vendors like OpenShift
// 							// be aware that you cannot run under its restricted-v2 SCC if you set this value.
// 							RunAsUser:                &[]int64{1001}[0],
// 							AllowPrivilegeEscalation: &[]bool{false}[0],
// 							Capabilities: &corev1.Capabilities{
// 								Drop: []corev1.Capability{
// 									"ALL",
// 								},
// 							},
// 						},
// 						Ports: []corev1.ContainerPort{{
// 							ContainerPort: memcached.Spec.ContainerPort,
// 							Name:          "memcached",
// 						}},
// 						Command: []string{"memcached", "-m=64", "-o", "modern", "-v"},
// 					}},
// 				},
// 			},
// 		},
// 	}

// 	// Set the ownerRef for the Deployment
// 	// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/owners-dependents/
// 	if err := ctrl.SetControllerReference(memcached, dep, r.Scheme); err != nil {
// 		return nil, err
// 	}
// 	return dep, nil
// }

// labelsForMemcached returns the labels for selecting the resources
// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/common-labels/
// func labelsForMemcached(name string) map[string]string {
// 	var imageTag string
// 	image, err := imageForMemcached()
// 	if err == nil {
// 		imageTag = strings.Split(image, ":")[1]
// 	}
// 	return map[string]string{"app.kubernetes.io/name": "memcached-operator",
// 		"app.kubernetes.io/version":    imageTag,
// 		"app.kubernetes.io/managed-by": "MemcachedController",
// 	}
// }

// imageForMemcached gets the Operand image which is managed by this controller
// from the MEMCACHED_IMAGE environment variable defined in the config/manager/manager.yaml
// func imageForMemcached() (string, error) {
// 	var imageEnvVar = "MEMCACHED_IMAGE"
// 	image, found := os.LookupEnv(imageEnvVar)
// 	if !found {
// 		return "", fmt.Errorf("Unable to find %s environment variable with the image", imageEnvVar)
// 	}
// 	return image, nil
// }

// SetupWithManager sets up the controller with the Manager.
// Note that the Deployment will be also watched in order to ensure its
// desirable state on the cluster
func (r *RolesReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&postgresqlv1alpha1.Roles{}).
		// Owns(&appsv1.Deployment{}).
		// WithOptions(controller.Options{MaxConcurrentReconciles: 2}).
		Complete(r)
}
