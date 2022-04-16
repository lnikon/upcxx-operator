package v1alpha1

import (
	"context"
	"log"
	"path/filepath"

	"github.com/lnikon/upcxx-operator/api/v1alpha1"
	ctrl "github.com/lnikon/upcxx-operator/controllers"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

func (c *UPCXXClient) List(opts metav1.ListOptions) (*v1alpha1.UPCXXList, error) {
	result := v1alpha1.UPCXXList{}
	err := c.restClient.
		Get().
		Namespace(c.ns).
		Resource("upcxxes").
		VersionedParams(&opts, metav1.ParameterCodec).
		Do(context.TODO()).
		Into(&result)

	return &result, err
}

func (c *UPCXXClient) Get(name string, opts metav1.GetOptions) (*v1alpha1.UPCXX, error) {
	result := v1alpha1.UPCXX{}
	err := c.restClient.
		Get().
		Namespace("default").
		Resource("upcxxes").
		Name(name).
		VersionedParams(&opts, metav1.ParameterCodec).
		Do(context.TODO()).
		Into(&result)

	if err != nil {
		log.Printf("Get Error: %s", err)
	}

	return &result, err
}

func (c *UPCXXClient) Create(upcxx *v1alpha1.UPCXX) (*v1alpha1.UPCXX, error) {
	result := v1alpha1.UPCXX{}
	err := c.restClient.
		Post().
		Namespace("default").
		Resource("upcxxes").
		VersionedParams(&metav1.CreateOptions{}, metav1.ParameterCodec).
		Body(upcxx).
		Do(context.TODO()).
		Into(&result)

	return &result, err
}

func (c *UPCXXClient) Delete(name string, options *metav1.DeleteOptions) (*v1alpha1.UPCXX, error) {
	res := c.restClient.
		Delete().
		Namespace("default").
		Resource("upcxxes").
		Name(name).
		Body(options).
		Do(context.TODO())

	return nil, res.Error()
}

func (c *UPCXXClient) GetLauncherService(name string) (*corev1.Service, error) {
	// config, err := rest.InClusterConfig()
	// if err != nil {
	// 	log.Println("GetLauncherService: Unable to create in cluster config")
	// 	return nil, err
	// }

	kubeconfig := filepath.Join(homedir.HomeDir(), ".kube", "config")
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		log.Printf("GetLauncherService: Can't create config from ~/.kube/config. Now will try to create in-cluster config.")
		config, err = rest.InClusterConfig()
		if err != nil {
			log.Printf("GetLauncherService: Can't create in-cluster config.")
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Println("GetLauncherService: Unable to create clientset")
		return nil, err
	}

	upcxx := v1alpha1.UPCXX{}
	upcxx.Spec.StatefulSetName = name

	svc, err := clientset.CoreV1().Services("default").Get(context.TODO(), ctrl.BuildLauncherJobName(&upcxx), metav1.GetOptions{})
	if err != nil {
		log.Printf("GetLauncherService: Unable to get service %s\n", ctrl.BuildLauncherJobName(&upcxx))
		return nil, err
	}

	return svc, err
}
