package deploycheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
)

// CheckObserved compares the admitted Deployment against the exact authorized
// restricted request. Only enumerated Kubernetes defaults and informational
// server metadata are normalized. Unknown workload fields fail closed. This is
// a point-in-time Deployment check, not running-Pod or continuous attestation.
func CheckObserved(requested, observed []byte, namespace, expectedDigest string) error {
	if err := Check(requested, namespace, expectedDigest); err != nil {
		return err
	}
	if len(observed) > 2<<20 {
		return errors.New("admitted Deployment exceeds limit")
	}
	if err := rejectDuplicateKeys(observed); err != nil {
		return err
	}
	var want, got map[string]any
	decode := func(data []byte, out *map[string]any) error {
		d := json.NewDecoder(bytes.NewReader(data))
		d.UseNumber()
		return d.Decode(out)
	}
	if decode(requested, &want) != nil || decode(observed, &got) != nil || got == nil {
		return errors.New("invalid admitted Deployment")
	}
	if err := normalizeObserved(got); err != nil {
		return err
	}
	if err := normalizeRequested(want); err != nil {
		return err
	}
	if !reflect.DeepEqual(want, got) {
		return errors.New("admitted Deployment differs from authorized supported profile")
	}
	return nil
}

func object(parent map[string]any, key string) (map[string]any, error) {
	v, ok := parent[key].(map[string]any)
	if !ok || v == nil {
		return nil, errors.New("missing or invalid workload object")
	}
	return v, nil
}
func defaultField(m map[string]any, key string, value any) error {
	if v, ok := m[key]; ok {
		if !reflect.DeepEqual(v, value) {
			return errors.New("unexpected admitted API default: " + key)
		}
		delete(m, key)
	}
	return nil
}
func zeroField(m map[string]any, key string, value any) {
	if v, ok := m[key]; ok && (v == nil || reflect.DeepEqual(v, value)) {
		delete(m, key)
	}
}
func emptyArray(m map[string]any, key string) {
	if v, ok := m[key]; ok {
		if v == nil {
			delete(m, key)
		} else if a, ok := v.([]any); ok && len(a) == 0 {
			delete(m, key)
		}
	}
}

func normalizeRequested(d map[string]any) error {
	spec, err := object(d, "spec")
	if err != nil {
		return err
	}
	template, err := object(spec, "template")
	if err != nil {
		return err
	}
	pod, err := object(template, "spec")
	if err != nil {
		return err
	}
	for _, k := range []string{"hostNetwork", "hostPID", "hostIPC"} {
		zeroField(pod, k, false)
	}
	zeroField(pod, "serviceAccountName", "")
	for _, k := range []string{"initContainers", "ephemeralContainers", "volumes"} {
		emptyArray(pod, k)
	}
	containers, ok := pod["containers"].([]any)
	if !ok || len(containers) != 1 {
		return errors.New("invalid admitted containers")
	}
	c, ok := containers[0].(map[string]any)
	if !ok {
		return errors.New("invalid admitted container")
	}
	security, err := object(c, "securityContext")
	if err != nil {
		return err
	}
	zeroField(security, "privileged", false)
	if caps, err := object(security, "capabilities"); err == nil {
		emptyArray(caps, "add")
	}
	return nil
}

var revision = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)

func normalizeObserved(d map[string]any) error {
	delete(d, "status") // status does not grant execution configuration authority
	metadata, err := object(d, "metadata")
	if err != nil {
		return err
	}
	for k, v := range metadata {
		switch k {
		case "name", "namespace":
		case "uid", "resourceVersion", "generation", "creationTimestamp", "managedFields":
			delete(metadata, k)
		case "deletionTimestamp":
			if v != nil {
				return errors.New("admitted Deployment is terminating")
			}
			delete(metadata, k)
		case "annotations":
			annotations, ok := v.(map[string]any)
			if !ok {
				return errors.New("unsupported admitted annotations")
			}
			for name, value := range annotations {
				r, ok := value.(string)
				if name != "deployment.kubernetes.io/revision" || !ok || !revision.MatchString(r) {
					return errors.New("unsupported admitted annotations")
				}
			}
			delete(metadata, k)
		default:
			return errors.New("unsupported admitted metadata")
		}
	}
	spec, err := object(d, "spec")
	if err != nil {
		return err
	}
	for k, v := range map[string]any{"progressDeadlineSeconds": json.Number("600"), "revisionHistoryLimit": json.Number("10"), "minReadySeconds": json.Number("0"), "paused": false} {
		if err = defaultField(spec, k, v); err != nil {
			return err
		}
	}
	strategy := map[string]any{"type": "RollingUpdate", "rollingUpdate": map[string]any{"maxUnavailable": "25%", "maxSurge": "25%"}}
	if err = defaultField(spec, "strategy", strategy); err != nil {
		return err
	}
	template, err := object(spec, "template")
	if err != nil {
		return err
	}
	tm, err := object(template, "metadata")
	if err != nil {
		return err
	}
	if v, ok := tm["creationTimestamp"]; ok {
		if v != nil {
			return errors.New("unexpected template timestamp")
		}
		delete(tm, "creationTimestamp")
	}
	pod, err := object(template, "spec")
	if err != nil {
		return err
	}
	for k, v := range map[string]any{"restartPolicy": "Always", "terminationGracePeriodSeconds": json.Number("30"), "dnsPolicy": "ClusterFirst", "schedulerName": "default-scheduler", "serviceAccountName": "default", "serviceAccount": "default", "enableServiceLinks": true, "preemptionPolicy": "PreemptLowerPriority"} {
		if err = defaultField(pod, k, v); err != nil {
			return err
		}
	}
	containers, ok := pod["containers"].([]any)
	if !ok || len(containers) != 1 {
		return errors.New("additional admitted execution denied")
	}
	c, ok := containers[0].(map[string]any)
	if !ok {
		return errors.New("invalid admitted container")
	}
	for k, v := range map[string]any{"imagePullPolicy": "IfNotPresent", "terminationMessagePath": "/dev/termination-log", "terminationMessagePolicy": "File", "resources": map[string]any{}} {
		if err = defaultField(c, k, v); err != nil {
			return err
		}
	}
	return normalizeRequested(d)
}
