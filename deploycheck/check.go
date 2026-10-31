package deploycheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strings"
)

// Deployment is an intentionally narrow Kubernetes apps/v1 Deployment model.
// Unknown fields are rejected to prevent an admission bypass through unexamined configuration.
type Deployment struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Spec struct {
		Replicas *int `json:"replicas"`
		Selector struct {
			MatchLabels map[string]string `json:"matchLabels"`
		} `json:"selector"`
		Template struct {
			Metadata struct {
				Labels map[string]string `json:"labels"`
			} `json:"metadata"`
			Spec struct {
				AutomountServiceAccountToken *bool  `json:"automountServiceAccountToken"`
				HostNetwork                  bool   `json:"hostNetwork"`
				HostPID                      bool   `json:"hostPID"`
				HostIPC                      bool   `json:"hostIPC"`
				ServiceAccountName           string `json:"serviceAccountName"`
				SecurityContext              struct {
					RunAsNonRoot   *bool `json:"runAsNonRoot"`
					SeccompProfile struct {
						Type string `json:"type"`
					} `json:"seccompProfile"`
				} `json:"securityContext"`
				Containers []struct {
					Name            string `json:"name"`
					Image           string `json:"image"`
					SecurityContext struct {
						Privileged               bool  `json:"privileged"`
						AllowPrivilegeEscalation *bool `json:"allowPrivilegeEscalation"`
						ReadOnlyRootFilesystem   *bool `json:"readOnlyRootFilesystem"`
						Capabilities             struct {
							Drop []string `json:"drop"`
							Add  []string `json:"add"`
						} `json:"capabilities"`
					} `json:"securityContext"`
				} `json:"containers"`
				InitContainers      []json.RawMessage `json:"initContainers"`
				EphemeralContainers []json.RawMessage `json:"ephemeralContainers"`
				Volumes             []json.RawMessage `json:"volumes"`
			} `json:"spec"`
		} `json:"template"`
	} `json:"spec"`
}

var digest = regexp.MustCompile(`^[a-f0-9]{64}$`)
var imageRef = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:/-]*@sha256:[a-f0-9]{64}$`)

// rejectDuplicateKeys recursively rejects ambiguous JSON object keys before decoding.
func rejectDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	var parse func() error
	parse = func() error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		d, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch d {
		case '{':
			seen := make(map[string]struct{})
			for dec.More() {
				key, err := dec.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok {
					return errors.New("invalid JSON object key")
				}
				if _, exists := seen[name]; exists {
					return fmt.Errorf("duplicate JSON key %q", name)
				}
				seen[name] = struct{}{}
				if err := parse(); err != nil {
					return err
				}
			}
		case '[':
			for dec.More() {
				if err := parse(); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid JSON delimiter")
		}
		_, err = dec.Token()
		return err
	}
	if err := parse(); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON documents")
		}
		return err
	}
	return nil
}

// Check validates a restricted single-container Deployment against a trusted observed
// OCI image digest. It is a preflight contract, not Kubernetes admission enforcement.
func Check(data []byte, namespace, expectedDigest string) error {
	if !digest.MatchString(expectedDigest) {
		return errors.New("invalid trusted image digest")
	}
	if len(data) > 1<<20 {
		return errors.New("deployment document exceeds 1 MiB")
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return err
	}
	if err := exactFields(data, reflect.TypeOf(Deployment{})); err != nil {
		return err
	}
	var d Deployment
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return fmt.Errorf("malformed or unsupported deployment: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err == nil {
		return errors.New("multiple JSON documents denied")
	} else if err != io.EOF {
		return fmt.Errorf("trailing JSON: %w", err)
	}
	if d.APIVersion != "apps/v1" || d.Kind != "Deployment" || d.Metadata.Namespace != namespace || namespace == "" || d.Metadata.Name == "" {
		return errors.New("resource identity denied")
	}
	if d.Spec.Replicas == nil || *d.Spec.Replicas < 1 || *d.Spec.Replicas > 10 {
		return errors.New("replicas denied")
	}
	p := d.Spec.Template.Spec
	if p.AutomountServiceAccountToken == nil || *p.AutomountServiceAccountToken || p.HostNetwork || p.HostPID || p.HostIPC || p.ServiceAccountName != "" {
		return errors.New("pod privileges denied")
	}
	if p.SecurityContext.RunAsNonRoot == nil || !*p.SecurityContext.RunAsNonRoot || p.SecurityContext.SeccompProfile.Type != "RuntimeDefault" {
		return errors.New("pod security context denied")
	}
	if len(p.Containers) != 1 || len(p.InitContainers) != 0 || len(p.EphemeralContainers) != 0 || len(p.Volumes) != 0 {
		return errors.New("additional execution or mounts denied")
	}
	c := p.Containers[0]
	if c.Name == "" || c.SecurityContext.Privileged || c.SecurityContext.AllowPrivilegeEscalation == nil || *c.SecurityContext.AllowPrivilegeEscalation || c.SecurityContext.ReadOnlyRootFilesystem == nil || !*c.SecurityContext.ReadOnlyRootFilesystem || len(c.SecurityContext.Capabilities.Add) != 0 {
		return errors.New("container privileges denied")
	}
	if len(c.SecurityContext.Capabilities.Drop) != 1 || c.SecurityContext.Capabilities.Drop[0] != "ALL" {
		return errors.New("capabilities must drop ALL")
	}
	parts := strings.Split(c.Image, "@sha256:")
	if len(parts) != 2 || !imageRef.MatchString(c.Image) || parts[1] != expectedDigest || strings.Contains(parts[0][strings.LastIndex(parts[0], "/")+1:], ":") {
		return errors.New("image digest mismatch or mutable tag")
	}
	if len(d.Spec.Selector.MatchLabels) == 0 {
		return errors.New("missing workload selector")
	}
	for k, v := range d.Spec.Selector.MatchLabels {
		if d.Spec.Template.Metadata.Labels[k] != v {
			return errors.New("selector mismatch")
		}
	}
	return nil
}

// encoding/json matches struct keys case-insensitively. Kubernetes field names
// are case-sensitive: reject alternate spellings rather than interpret a manifest
// differently from the API server. Free-form label maps retain their own casing.
func exactFields(data []byte, typ reflect.Type) error {
	if typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	switch typ.Kind() {
	case reflect.Struct:
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(data, &obj); err != nil {
			return err
		}
		fields := make(map[string]reflect.Type)
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			fields[strings.Split(f.Tag.Get("json"), ",")[0]] = f.Type
		}
		for k, v := range obj {
			field, ok := fields[k]
			if !ok {
				return fmt.Errorf("unsupported exact JSON field %q", k)
			}
			if err := exactFields(v, field); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if typ == reflect.TypeOf(json.RawMessage{}) {
			return nil
		}
		var values []json.RawMessage
		if err := json.Unmarshal(data, &values); err != nil {
			return err
		}
		for _, v := range values {
			if err := exactFields(v, typ.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}
