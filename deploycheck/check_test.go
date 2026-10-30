package deploycheck

import (
	"encoding/json"
	"strings"
	"testing"
)

const hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func valid() map[string]any {
	return map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": map[string]any{"name": "sample", "namespace": "staging"}, "spec": map[string]any{"replicas": 1, "selector": map[string]any{"matchLabels": map[string]any{"app": "sample"}}, "template": map[string]any{"metadata": map[string]any{"labels": map[string]any{"app": "sample"}}, "spec": map[string]any{"automountServiceAccountToken": false, "hostNetwork": false, "hostPID": false, "hostIPC": false, "runAsUser": nil, "securityContext": map[string]any{"runAsNonRoot": true, "seccompProfile": map[string]any{"type": "RuntimeDefault"}}, "containers": []any{map[string]any{"name": "app", "image": "example.com/app@sha256:" + hash, "securityContext": map[string]any{"privileged": false, "allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "capabilities": map[string]any{"drop": []string{"ALL"}, "add": []string{}}}}}}}}}
}
func render(m map[string]any) []byte { b, _ := json.Marshal(m); return b }
func pod(m map[string]any) map[string]any {
	return m["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
}
func TestContract(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
		ok     bool
	}{
		{"valid", func(m map[string]any) { delete(pod(m), "runAsUser") }, true},
		{"mutable tag", func(m map[string]any) {
			delete(pod(m), "runAsUser")
			pod(m)["containers"].([]any)[0].(map[string]any)["image"] = "example.com/app:latest"
		}, false},
		{"wrong digest", func(m map[string]any) {
			delete(pod(m), "runAsUser")
			pod(m)["containers"].([]any)[0].(map[string]any)["image"] = "example.com/app@sha256:" + strings.Repeat("b", 64)
		}, false},
		{"host network", func(m map[string]any) { delete(pod(m), "runAsUser"); pod(m)["hostNetwork"] = true }, false},
		{"service account token", func(m map[string]any) { delete(pod(m), "runAsUser"); pod(m)["automountServiceAccountToken"] = true }, false},
		{"privileged", func(m map[string]any) {
			delete(pod(m), "runAsUser")
			pod(m)["containers"].([]any)[0].(map[string]any)["securityContext"].(map[string]any)["privileged"] = true
		}, false},
		{"unknown field", func(m map[string]any) { pod(m)["bypassFlag"] = true }, false},
		{"extra container", func(m map[string]any) {
			delete(pod(m), "runAsUser")
			cs := pod(m)["containers"].([]any)
			pod(m)["containers"] = append(cs, cs[0])
		}, false},
		{"host path volume", func(m map[string]any) {
			delete(pod(m), "runAsUser")
			pod(m)["volumes"] = []any{map[string]any{"hostPath": map[string]any{"path": "/"}}}
		}, false},
		{"wrong namespace", func(m map[string]any) {
			delete(pod(m), "runAsUser")
			m["metadata"].(map[string]any)["namespace"] = "production"
		}, false},
		{"privilege escalation", func(m map[string]any) {
			delete(pod(m), "runAsUser")
			pod(m)["containers"].([]any)[0].(map[string]any)["securityContext"].(map[string]any)["allowPrivilegeEscalation"] = true
		}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := valid()
			tc.mutate(m)
			err := Check(render(m), "staging", hash)
			if (err == nil) != tc.ok {
				t.Fatalf("want success=%v, got %v", tc.ok, err)
			}
		})
	}
}
