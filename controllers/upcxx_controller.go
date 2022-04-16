/*
Copyright 2021.

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

package controllers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"

	"github.com/go-logr/logr"
	"golang.org/x/crypto/ssh"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	pgasv1alpha1 "github.com/lnikon/upcxx-operator/api/v1alpha1"

	"fmt"
	"strings"
)

// Container that contains UPCXX graphs library and application
const (
	UPCXXContainerName       = "pgasgraph"
	UPCXXContainerTagLatest  = ":latest"
	UPCXXLatestContainerName = UPCXXContainerName + UPCXXContainerTagLatest

	GLCSContainerName       = "glcs"
	GLCSContainerTagLatest  = ":latest"
	GLCSLatestContainerName = GLCSContainerName + GLCSContainerTagLatest

	// Launcher specific definitions
	launcherSuffix = "-launcher"

	// Worker specific definitions
	workerSuffix = "-worker"

	// SSH
	sshAuthSecretSuffix   = "-ssh"
	sshAuthVolume         = "ssh-auth"
	sshPublicKey          = "ssh-publickey"
	sshPrivateKeyFile     = "id_rsa"
	sshPublicKeyFile      = sshPrivateKeyFile + ".pub"
	sshAuthorizedKeysFile = "authorized_keys"
	sshKnownHosts         = "known_hosts"
	sshKnownHostsFile     = "known_hosts"
)

var (
	sshVolumeItems = []core.KeyToPath{
		{
			Key:  core.SSHAuthPrivateKey,
			Path: sshPrivateKeyFile,
		},
		{
			Key:  sshPublicKey,
			Path: sshPublicKeyFile,
		},
		{
			Key:  sshPublicKey,
			Path: sshAuthorizedKeysFile,
		},
		{
			Key:  sshKnownHosts,
			Path: sshKnownHostsFile,
		},
	}
)

// UPCXXReconciler reconciles a UPCXX object
type UPCXXReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
	Log      logr.Logger
}

//+kubebuilder:rbac:groups=pgas.github.com,resources=upcxxes,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=pgas.github.com,resources=upcxxes/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=pgas.github.com,resources=upcxxes/finalizers,verbs=update
//+kubebuilder:rbac:groups=*,resources=upcxxes,verbs=get;list;watch;create;update;
//+kubebuilder:rbac:groups=*,resources=configmaps,verbs=get;list;watch;create;update;
//+kubebuilder:rbac:groups=*,resources=services,verbs=get;list;watch;create;update;
//+kubebuilder:rbac:groups=*,resources=events,verbs=get;list;watch;create;update;
//+kubebuilder:rbac:groups=*,resources=statefulsets,verbs=get;list;watch;create;update;
//+kubebuilder:rbac:groups=*,resources=jobs,verbs=get;list;watch;create;update;
//+kubebuilder:rbac:groups=*,resources=deployments,verbs=get;list;watch;create;update;

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// the UPCXX object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.9.2/pkg/reconcile
func (r *UPCXXReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)
	logger := r.Log.WithValues("UPCXX", req.NamespacedName)

	upcxx := pgasv1alpha1.UPCXX{}
	if err := r.Client.Get(ctx, req.NamespacedName, &upcxx); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
	}

	if _, err := r.getOrCreateSSHAuthSecret(&upcxx); err != nil {
		logger.Error(err, "creating SSH auth secret")
	}

	launcherService := &core.Service{}
	err := r.Client.Get(ctx, client.ObjectKey{Namespace: upcxx.Namespace, Name: BuildLauncherJobName(&upcxx)}, launcherService)
	if apierrors.IsNotFound(err) {
		logger.Info("Could not find existing Service for launcher Job")

		launcherService = buildLauncherService(&upcxx)
		if err := r.Client.Create(ctx, launcherService); err != nil {
			logger.Error(err, "Unable to create Service for Launcher Job")
			return ctrl.Result{}, err
		}

		r.Recorder.Eventf(&upcxx, core.EventTypeNormal, "Created Service for launcher Job", BuildLauncherJobName(&upcxx))
	}

	logger = logger.WithValues("StatefulSetName", upcxx.Spec.StatefulSetName)
	statefulSet := &apps.StatefulSet{}
	err = r.Client.Get(ctx, client.ObjectKey{Namespace: upcxx.Namespace, Name: buildWorkerPodName(&upcxx)}, statefulSet)
	if apierrors.IsNotFound(err) {
		logger.Info("Could not find existing StatefulSet for", "resource", buildWorkerPodName(&upcxx))
		statefulSet = buildWorkerStatefulSet(&upcxx)

		if err := r.Client.Create(ctx, statefulSet); err != nil {
			logger.Error(err, "Failed to create StatefulSet", "resource", buildWorkerPodName(&upcxx))
			return ctrl.Result{}, err
		}

		r.Recorder.Eventf(&upcxx, core.EventTypeNormal, "Created StatefulSet", buildWorkerPodName(&upcxx))
	}

	launcherJob := &apps.Deployment{}
	err = r.Client.Get(ctx, client.ObjectKey{Namespace: upcxx.Namespace, Name: BuildLauncherJobName(&upcxx)}, launcherJob)
	if apierrors.IsNotFound(err) {
		logger.Info("Could not find existing Job for launcher job")

		launcherJob = buildLauncherJob(&upcxx)
		if err := r.Client.Create(ctx, launcherJob); err != nil {
			logger.Error(err, "Failed to create Job for launcher pod")
			return ctrl.Result{}, err
		}

		r.Recorder.Eventf(&upcxx, core.EventTypeNormal, "Created Job for launcher", BuildLauncherJobName(&upcxx))
	}

	return ctrl.Result{}, nil
}

func BuildLauncherJobName(upcxx *pgasv1alpha1.UPCXX) string {
	return upcxx.Spec.StatefulSetName + launcherSuffix
}

func buildLauncherJob(upcxx *pgasv1alpha1.UPCXX) *apps.Deployment {
	controllerRef := *meta.NewControllerRef(upcxx, pgasv1alpha1.GroupVersion.WithKind("UPCXX"))
	launcherJobSpec := &apps.Deployment{
		ObjectMeta: meta.ObjectMeta{
			Name:      BuildLauncherJobName(upcxx),
			Namespace: upcxx.ObjectMeta.Namespace,
			Labels: map[string]string{
				"app": BuildLauncherJobName(upcxx),
				"hpc": "upcxx",
			},
			OwnerReferences: []meta.OwnerReference{controllerRef},
		},
		Spec: apps.DeploymentSpec{
			Replicas: int32ToPtr(1),
			Selector: &meta.LabelSelector{
				MatchLabels: map[string]string{
					"app": BuildLauncherJobName(upcxx),
					"hpc": "upcxx",
				},
			},
			Template: core.PodTemplateSpec{
				ObjectMeta: meta.ObjectMeta{
					Name: BuildLauncherJobName(upcxx),
					Labels: map[string]string{
						"app": BuildLauncherJobName(upcxx),
						"hpc": "upcxx",
					},
				},
				Spec: core.PodSpec{
					Hostname: BuildLauncherJobName(upcxx),
					Volumes: []core.Volume{
						{
							Name: "shared-workspace",
							VolumeSource: core.VolumeSource{
								EmptyDir: &core.EmptyDirVolumeSource{},
							},
						},
					},
					Containers: []core.Container{
						{
							Name:            UPCXXContainerName,
							Image:           UPCXXLatestContainerName,
							ImagePullPolicy: "Never",
							Env:             createEnvVars(upcxx),
							VolumeMounts: []core.VolumeMount{
								{
									Name:      "shared-workspace",
									MountPath: "/shared-workspace",
								},
							},
						},
						{
							Name:            GLCSContainerName,
							Image:           GLCSLatestContainerName,
							ImagePullPolicy: "Never",
							Env:             createEnvVars(upcxx),
							VolumeMounts: []core.VolumeMount{
								{
									Name:      "shared-workspace",
									MountPath: "/shared-workspace",
								},
							},
							Ports: []core.ContainerPort{
								{
									ContainerPort: 30001,
									HostPort:      30001,
									Protocol:      core.ProtocolTCP,
								},
							},
						},
					},
				},
			},
		},
	}

	//launcherJobSpec.Spec.Template.Spec.Containers[0].Env = append(launcherJobSpec.Spec.Template.Spec.Containers[0].Env, createEnvVars(upcxx)...)
	setupSSHOnPod(&launcherJobSpec.Spec.Template.Spec, upcxx)

	return launcherJobSpec
}

func buildWorkerPodName(upcxx *pgasv1alpha1.UPCXX) string {
	return upcxx.Spec.StatefulSetName + workerSuffix
}

func buildWorkerStatefulSet(upcxx *pgasv1alpha1.UPCXX) *apps.StatefulSet {
	controllerRef := *meta.NewControllerRef(upcxx, pgasv1alpha1.GroupVersion.WithKind("UPCXX"))
	statefulSet := apps.StatefulSet{
		ObjectMeta: meta.ObjectMeta{
			// TODO: Should we pass sts name in the yaml? It can be same as the resource name or with -sts postfix.
			Name:            buildWorkerPodName(upcxx),
			Namespace:       upcxx.Namespace,
			OwnerReferences: []meta.OwnerReference{controllerRef},
		},
		Spec: apps.StatefulSetSpec{
			ServiceName: buildWorkerPodName(upcxx),
			Replicas:    getWorkerCount(upcxx),
			Selector: &meta.LabelSelector{
				MatchLabels: map[string]string{
					"app": buildWorkerPodName(upcxx),
				},
			},
			Template: core.PodTemplateSpec{
				ObjectMeta: meta.ObjectMeta{
					Name: buildWorkerPodName(upcxx),
					Labels: map[string]string{
						"app": buildWorkerPodName(upcxx),
						"hpc": "upcxx",
					},
				},
				Spec: core.PodSpec{
					Hostname: buildWorkerPodName(upcxx),
					Volumes: []core.Volume{
						{
							Name: "empty-dir-vm",
							VolumeSource: core.VolumeSource{
								EmptyDir: &core.EmptyDirVolumeSource{},
							},
						},
						{
							Name: "shared-workspace-worker",
							VolumeSource: core.VolumeSource{
								EmptyDir: &core.EmptyDirVolumeSource{},
							},
						},
					},
					Containers: []core.Container{
						{
							Name:  UPCXXContainerName,
							Image: UPCXXLatestContainerName,
							// TODO: Pass using UPCXX resource. Set default to IfNotPresent.
							ImagePullPolicy: "Never",
							VolumeMounts: []core.VolumeMount{
								{
									Name:      upcxx.Spec.StatefulSetName + "-vm",
									MountPath: "/vmount",
								},
								{
									Name:      "shared-workspace-worker",
									MountPath: "/shared-workspace",
								},
							},
						},
					},
				},
			},
			VolumeClaimTemplates: []core.PersistentVolumeClaim{
				{
					ObjectMeta: meta.ObjectMeta{
						Name:            upcxx.Spec.StatefulSetName + "-vm",
						Namespace:       upcxx.Namespace,
						OwnerReferences: []meta.OwnerReference{controllerRef},
					},
					Spec: core.PersistentVolumeClaimSpec{
						AccessModes: []core.PersistentVolumeAccessMode{
							core.ReadWriteMany,
						},
						Resources: core.ResourceRequirements{
							Requests: core.ResourceList{
								core.ResourceStorage: *resource.NewQuantity(500, resource.BinarySI),
							},
						},
					},
				},
			},
		},
	}

	statefulSet.Spec.Template.Spec.Containers[0].Env = append(statefulSet.Spec.Template.Spec.Containers[0].Env, createEnvVars(upcxx)...)
	setupSSHOnPod(&statefulSet.Spec.Template.Spec, upcxx)

	return &statefulSet
}

func createSSHServersEnv(upcxx *pgasv1alpha1.UPCXX) (core.EnvVar, []string) {
	var sshServersList []string
	sshServersList = append(sshServersList, BuildLauncherJobName(upcxx))
	workerName := buildWorkerPodName(upcxx)
	for idx := int32(0); idx < upcxx.Spec.WorkerCount-1; idx++ {
		sshServersList = append(sshServersList, fmt.Sprintf("%s-%d.%s.%s", workerName, idx, workerName, "default.svc.cluster.local"))
	}

	return core.EnvVar{Name: "SSH_SERVERS", Value: strings.Join(sshServersList, ",")}, sshServersList
}

func createEnvVars(upcxx *pgasv1alpha1.UPCXX) []core.EnvVar {
	sshServersEnv, sshServerList := createSSHServersEnv(upcxx)
	return []core.EnvVar{
		sshServersEnv,
		{
			Name:  "GASNET_SSH_SERVERS",
			Value: sshServersEnv.Value,
		},
		{
			Name:  "GASNET_MASTERIP",
			Value: sshServerList[0],
		},
		{
			Name:  "UPCXX_NETWORK",
			Value: "udp",
		},
		{
			Name:  "GASNET_SPAWNFN",
			Value: "S",
		},
		{
			Name:  "DB_HOST",
			Value: "postgres",
		},
		{
			Name:  "DB_PORT",
			Value: "5432",
		},
		{
			Name:  "DB_USER",
			Value: "postgres",
		},
		{
			Name:  "DB_PASSWORD",
			Value: "postgres",
		},
		{
			Name:  "DB_NAME",
			Value: "postgres",
		},
	}
}

func getWorkerCount(upcxx *pgasv1alpha1.UPCXX) *int32 {
	workerCount := upcxx.Spec.WorkerCount - 1
	return &workerCount
}

func buildLauncherService(upcxx *pgasv1alpha1.UPCXX) *core.Service {
	return newService(upcxx, BuildLauncherJobName(upcxx))
}

func newService(upcxx *pgasv1alpha1.UPCXX, name string) *core.Service {
	return &core.Service{
		ObjectMeta: meta.ObjectMeta{
			Name:      name,
			Namespace: upcxx.Namespace,
			Labels: map[string]string{
				"app": name,
			},
			OwnerReferences: []meta.OwnerReference{
				*meta.NewControllerRef(upcxx, pgasv1alpha1.GroupVersion.WithKind("UPCXX")),
			},
		},
		Spec: core.ServiceSpec{
			Type: core.ServiceTypeLoadBalancer,
			Ports: []core.ServicePort{
				{
					Port:       30001,
					TargetPort: intstr.IntOrString{Type: intstr.Int, IntVal: 30001},
					Protocol:   core.ProtocolTCP,
				},
			},
			Selector: map[string]string{
				"app": name,
			},
		},
	}
}

// getOrCreateSSHAuthSecret gets the Secret holding the SSH auth for this job,
// or create one if it doesn't exist.
func (r *UPCXXReconciler) getOrCreateSSHAuthSecret(job *pgasv1alpha1.UPCXX) (*core.ConfigMap, error) {
	secret := &core.ConfigMap{}
	err := r.Get(context.TODO(), client.ObjectKey{Namespace: job.Namespace,
		Name: job.Spec.StatefulSetName + sshAuthSecretSuffix}, secret)
	if apierrors.IsNotFound(err) {
		secret, err = newSSHAuthSecret(job)
		if err != nil {
			return nil, err
		}
		if err := r.Create(context.TODO(), secret); err != nil {
			return nil, err
		}
	}

	if err != nil {
		return nil, err
	}

	return secret, nil
}

// newSSHAuthSecret creates a new Secret that holds SSH auth: a private Key
// and its public key version.
func newSSHAuthSecret(job *pgasv1alpha1.UPCXX) (*core.ConfigMap, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating private SSH key: %w", err)
	}
	privateDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("converting private SSH key to DER format: %w", err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateDER,
	})

	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("generating public SSH key: %w", err)
	}

	return &core.ConfigMap{
		ObjectMeta: meta.ObjectMeta{
			Name:      job.Spec.StatefulSetName + sshAuthSecretSuffix,
			Namespace: job.Namespace,
			Labels: map[string]string{
				"app": job.Spec.StatefulSetName,
			},
			OwnerReferences: []meta.OwnerReference{
				*meta.NewControllerRef(job, pgasv1alpha1.GroupVersion.WithKind("UPCXX")),
			},
		},

		BinaryData: map[string][]byte{
			core.SSHAuthPrivateKey: privatePEM,
			sshPublicKey:           ssh.MarshalAuthorizedKey(publicKey),
			sshKnownHosts:          {},
		},
	}, nil
}

func setupSSHOnPod(podSpec *core.PodSpec, job *pgasv1alpha1.UPCXX) {
	mainContainer := &podSpec.Containers[0]
	mode := int32ToPtr(0666)
	podSpec.Volumes = append(podSpec.Volumes,
		core.Volume{
			Name: sshAuthVolume,
			VolumeSource: core.VolumeSource{
				ConfigMap: &core.ConfigMapVolumeSource{
					DefaultMode: mode,
					LocalObjectReference: core.LocalObjectReference{
						Name: job.Spec.StatefulSetName + sshAuthSecretSuffix,
					},
					Items: sshVolumeItems,
				},
			},
		})

	mainContainer.VolumeMounts = append(mainContainer.VolumeMounts,
		core.VolumeMount{
			Name: sshAuthVolume,
			//MountPath: originalSSHPath,
			MountPath: "/home/upcxx/ssh-keys",
			ReadOnly:  true,
		})
}

func int32ToPtr(i int32) *int32 {
	return &i
}

func int64ToPtr(i int64) *int64 {
	return &i
}

// SetupWithManager sets up the controller with the Manager.
func (r *UPCXXReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&pgasv1alpha1.UPCXX{}).
		Complete(r)
}
