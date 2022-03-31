package v1alpha1

import (
	"context"

	"github.com/lnikon/upcxx-operator/api/v1alpha1"
	ctrl "github.com/lnikon/upcxx-operator/controllers"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	result := v1alpha1.UPCXX{}
	err := c.restClient.
		Delete().
		Namespace("default").
		Resource("upcxxes").
		Name(name).
		Body(options).
		Do(context.TODO()).
		Into(&result)

	return &result, err
}

func (c *UPCXXClient) GetLauncherService(name string) (*corev1.Service, error) {
	upcxx := v1alpha1.UPCXX{}
	upcxx.Spec.StatefulSetName = name

	result := corev1.Service{}
	err := c.restClient.
		Get().
		Namespace("default").
		Name(ctrl.BuildLauncherJobName(&upcxx)).
		Do(context.TODO()).
		Into(&result)

	return &result, err
}
