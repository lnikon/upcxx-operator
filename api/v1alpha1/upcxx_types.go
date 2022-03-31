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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// UPCXXSpec defines the desired state of UPCXX
type UPCXXSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Name of the current UPCXX job deployment
	StatefulSetName string `json:"statefulSetName"`

	// Count of worker pods
	WorkerCount int32 `json:"workerCount"`
}

// UPCXXStatus defines the observed state of UPCXX
type UPCXXStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

// +genclient:nonNamespaced
//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// UPCXX is the Schema for the upcxxes API
type UPCXX struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   UPCXXSpec   `json:"spec,omitempty"`
	Status UPCXXStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// UPCXXList contains a list of UPCXX
type UPCXXList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []UPCXX `json:"items"`
}

func init() {
	SchemeBuilder.Register(&UPCXX{}, &UPCXXList{})
}
