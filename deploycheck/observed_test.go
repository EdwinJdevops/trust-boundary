package deploycheck

import (
	"encoding/json"
	"testing"
)

func admittedFixture() ([]byte, map[string]any) {
	m := valid()
	delete(pod(m), "runAsUser")
	b := render(m)
	var got map[string]any
	_ = json.Unmarshal(b, &got)
	meta := got["metadata"].(map[string]any)
	meta["uid"] = "uid-1"
	meta["resourceVersion"] = "42"
	meta["annotations"] = map[string]any{"deployment.kubernetes.io/revision": "1"}
	got["status"] = map[string]any{"replicas": 1}
	spec := got["spec"].(map[string]any)
	spec["revisionHistoryLimit"] = 10
	spec["progressDeadlineSeconds"] = 600
	spec["strategy"] = map[string]any{"type": "RollingUpdate", "rollingUpdate": map[string]any{"maxUnavailable": "25%", "maxSurge": "25%"}}
	p := pod(got)
	p["restartPolicy"] = "Always"
	p["dnsPolicy"] = "ClusterFirst"
	p["serviceAccountName"] = "default"
	p["schedulerName"] = "default-scheduler"
	p["terminationGracePeriodSeconds"] = 30
	c := p["containers"].([]any)[0].(map[string]any)
	c["imagePullPolicy"] = "IfNotPresent"
	c["resources"] = map[string]any{}
	return b, got
}
func TestObservedDefaultsAndMutations(t *testing.T) {
	tests := map[string]func(map[string]any){
		"privilege injection": func(m map[string]any) {
			pod(m)["containers"].([]any)[0].(map[string]any)["securityContext"].(map[string]any)["privileged"] = true
		},
		"env injection": func(m map[string]any) {
			pod(m)["containers"].([]any)[0].(map[string]any)["env"] = []any{map[string]any{"name": "SECRET", "valueFrom": map[string]any{"secretKeyRef": map[string]any{"name": "secret", "key": "key"}}}}
		},
		"command injection":    func(m map[string]any) { pod(m)["containers"].([]any)[0].(map[string]any)["command"] = []any{"/bin/sh"} },
		"sidecar injection":    func(m map[string]any) { cs := pod(m)["containers"].([]any); pod(m)["containers"] = append(cs, cs[0]) },
		"init injection":       func(m map[string]any) { pod(m)["initContainers"] = []any{map[string]any{"name": "init"}} },
		"mount injection":      func(m map[string]any) { pod(m)["volumes"] = []any{map[string]any{"name": "data"}} },
		"account substitution": func(m map[string]any) { pod(m)["serviceAccountName"] = "privileged" },
		"token mount":          func(m map[string]any) { pod(m)["automountServiceAccountToken"] = true },
		"replica mutation":     func(m map[string]any) { m["spec"].(map[string]any)["replicas"] = 2 },
		"scheduler mutation":   func(m map[string]any) { pod(m)["schedulerName"] = "other" },
		"template annotation": func(m map[string]any) {
			m["spec"].(map[string]any)["template"].(map[string]any)["metadata"].(map[string]any)["annotations"] = map[string]any{"inject": "true"}
		},
		"terminating object": func(m map[string]any) { m["metadata"].(map[string]any)["deletionTimestamp"] = "2026-11-01T00:00:00Z" },
		"case alias":         func(m map[string]any) { pod(m)["HostNetwork"] = false },
	}
	request, m := admittedFixture()
	if err := CheckObserved(request, render(m), "staging", hash); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			request, m := admittedFixture()
			mutate(m)
			if err := CheckObserved(request, render(m), "staging", hash); err == nil {
				t.Fatal("admission mutation accepted")
			}
		})
	}
}
