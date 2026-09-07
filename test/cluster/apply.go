//go:build cluster

// Copyright (c) 2026 Damien Daly. All rights reserved.

package cluster

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// fieldOwner identifies the test as the owner of what it applies, so a
// server-side apply does not fight with whatever else touched the object.
const fieldOwner = client.FieldOwner("mailout-cluster-test")

// applyYAML server-side applies every document of a multi-document manifest.
// This is what `kubectl apply -f` does, minus the binary: the test needs to
// install cert-manager and the operator's own kustomize output, both of which
// are plain YAML streams.
func applyYAML(t *testing.T, c client.Client, raw []byte) {
	t.Helper()
	decoder := yaml.NewYAMLReader(bufio.NewReaderSize(bytes.NewReader(raw), 4096))
	applied := 0
	for {
		doc, err := decoder.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read manifest: %v", err)
		}
		if len(bytes.TrimSpace(doc)) == 0 {
			continue
		}
		obj := &unstructured.Unstructured{}
		if err := yaml.Unmarshal(doc, obj); err != nil {
			t.Fatalf("parse manifest document: %v", err)
		}
		if obj.GetKind() == "" {
			// Comment-only or empty document.
			continue
		}
		if err := c.Patch(t.Context(), obj, client.Apply, fieldOwner, client.ForceOwnership); err != nil {
			t.Fatalf("apply %s %s/%s: %v", obj.GetKind(), obj.GetNamespace(), obj.GetName(), err)
		}
		applied++
	}
	t.Logf("applied %d objects", applied)
}

// certManagerVersion is the release installed in the test cluster.
const certManagerVersion = "v1.21.1"

// certManagerManifest downloads the release manifest, cached between runs: it
// is several megabytes and does not change for a given version.
func certManagerManifest(t *testing.T) []byte {
	t.Helper()
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = os.TempDir()
	}
	cacheDir = filepath.Join(cacheDir, "mailout-cluster-test")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		t.Fatalf("create cache dir: %v", err)
	}
	cached := filepath.Join(cacheDir, "cert-manager-"+certManagerVersion+".yaml")
	if raw, err := os.ReadFile(cached); err == nil && len(raw) > 0 {
		return raw
	}

	url := fmt.Sprintf("https://github.com/cert-manager/cert-manager/releases/download/%s/cert-manager.yaml",
		certManagerVersion)
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("download cert-manager %s: %v", certManagerVersion, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("download cert-manager %s: HTTP %d", certManagerVersion, resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read cert-manager manifest: %v", err)
	}
	if err := os.WriteFile(cached, raw, 0o644); err != nil {
		t.Logf("cache cert-manager manifest: %v", err)
	}
	return raw
}

// kustomizeBuild renders one of the repository's kustomizations, with the image
// replaced by the one under test.
func kustomizeBuild(t *testing.T, dir string) []byte {
	t.Helper()
	// The repository declares kustomize as a Go tool, so there is nothing to
	// install for this to work.
	cmd := exec.Command("go", "tool", "kustomize", "build", dir)
	cmd.Dir = filepath.Join("..", "..")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("kustomize build %s: %v\n%s", dir, err, stderr.String())
	}
	// config/default pins the released image; the test runs the local build.
	return bytes.ReplaceAll(out,
		[]byte("ghcr.io/maitredede/mailout-operator:dev"), []byte(testImage()))
}

// waitForCondition polls an unstructured object until one of its status
// conditions has the wanted status.
func waitForCondition(t *testing.T, c client.Client, obj *unstructured.Unstructured,
	conditionType, want string, timeout time.Duration) {
	t.Helper()
	key := client.ObjectKeyFromObject(obj)
	deadline := time.Now().Add(timeout)
	last := "<none>"
	for time.Now().Before(deadline) {
		fresh := obj.DeepCopy()
		if err := c.Get(t.Context(), key, fresh); err == nil {
			conditions, found, _ := unstructured.NestedSlice(fresh.Object, "status", "conditions")
			if found {
				for _, entry := range conditions {
					condition, ok := entry.(map[string]any)
					if !ok || condition["type"] != conditionType {
						continue
					}
					status, _ := condition["status"].(string)
					if status == want {
						return
					}
					last = fmt.Sprintf("%s=%s (%v)", conditionType, status, condition["message"])
				}
			}
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("%s %s: condition %s never became %s within %s; last seen %s",
		obj.GetKind(), key, conditionType, want, timeout, last)
}

// waitForDeploymentsAvailable blocks until every named Deployment has an
// available replica.
func (cl *cluster) waitForDeploymentsAvailable(t *testing.T, namespace string, names []string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	pending := append([]string(nil), names...)
	for time.Now().Before(deadline) {
		var still []string
		for _, name := range pending {
			deployment, err := cl.Clientset.AppsV1().Deployments(namespace).
				Get(t.Context(), name, metav1.GetOptions{})
			if err != nil || deployment.Status.AvailableReplicas == 0 {
				still = append(still, name)
			}
		}
		if len(still) == 0 {
			return
		}
		pending = still
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("these Deployments in %s never became available within %s: %s",
		namespace, timeout, strings.Join(pending, ", "))
}

// waitForReadyReplicas waits until a Deployment has the expected number of
// ready pods. Distinct from waitForDeploymentsAvailable, which is satisfied by
// a single replica: for the operator's high availability, one ready pod is
// exactly the failure being looked for.
func (cl *cluster) waitForReadyReplicas(t *testing.T, namespace, name string, want int32, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last int32
	for time.Now().Before(deadline) {
		deployment, err := cl.Clientset.AppsV1().Deployments(namespace).
			Get(t.Context(), name, metav1.GetOptions{})
		if err == nil {
			last = deployment.Status.ReadyReplicas
			if last >= want {
				return
			}
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("%s/%s had %d ready replicas after %s, want %d", namespace, name, last, timeout, want)
}
