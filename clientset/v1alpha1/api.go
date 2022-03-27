package v1alpha1

import (
	"github.com/lnikon/upcxx-operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
)

type UPCXXInterface interface {
	List(opts metav1.ListOptions) (*v1alpha1.UPCXXList, error)
	Get(string, metav1.GetOptions) (*v1alpha1.UPCXX, error)
	Create(*v1alpha1.UPCXX) (*v1alpha1.UPCXX, error)
	Delete(string, *metav1.DeleteOptions) (*v1alpha1.UPCXX, error)
}

type UPCXXClient struct {
	restClient rest.Interface
	ns         string
}

func NewForConfig(c *rest.Config) (*UPCXXClient, error) {
	config := *c
	config.ContentConfig.GroupVersion = &v1alpha1.GroupVersion
	config.APIPath = "/apis"
	config.NegotiatedSerializer = scheme.Codecs.WithoutConversion()
	config.UserAgent = rest.DefaultKubernetesUserAgent()

	client, err := rest.RESTClientFor(&config)
	if err != nil {
		return nil, err
	}

	return &UPCXXClient{restClient: client}, nil
}

func (c *UPCXXClient) UPCXX(namespace string) UPCXXInterface {
	upcxxClient := &UPCXXClient{
		restClient: c.restClient,
		ns:         namespace,
	}
	return upcxxClient
}
