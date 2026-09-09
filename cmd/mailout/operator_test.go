// Copyright (c) 2026 Damien Daly. All rights reserved.

package main

import (
	"testing"

	"github.com/maitredede/mailout-operator/internal/render"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The Secret cache selects on a label, and anyone can put that label on their
// own Secret. Six hundred labelled Secrets of a megabyte each would be held in
// memory against a 512Mi limit, so the operator would OOMKill in a loop and
// nothing would reconcile for anyone. Keeping only the two keys the operator
// reads makes such a Secret cost a couple of hundred bytes whatever is in it.
func TestCachedSecretsKeepOnlyTheKeysWeRead(t *testing.T) {
	planted := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "planted", Namespace: "somewhere"},
		Data: map[string][]byte{
			corev1.BasicAuthPasswordKey: []byte("secret"),
			render.PasswordHashKey:      []byte("$2a$12$hash"),
			"junk":                      make([]byte, 1<<20),
		},
		StringData: map[string]string{"more": "junk"},
	}

	out, err := keepOnlyCredentialKeys(planted)
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	secret, ok := out.(*corev1.Secret)
	if !ok {
		t.Fatalf("transform returned %T", out)
	}

	if _, found := secret.Data["junk"]; found {
		t.Error("a megabyte of junk entered the cache")
	}
	if secret.StringData != nil {
		t.Error("StringData entered the cache")
	}
	// And what the operator actually reads survives: without the password, a
	// reconcile would regenerate it and break every application on each pass.
	for _, key := range []string{corev1.BasicAuthPasswordKey, render.PasswordHashKey} {
		if _, found := secret.Data[key]; !found {
			t.Errorf("%s was dropped, which the operator needs", key)
		}
	}
}

// Anything that is not a Secret passes through untouched.
func TestTransformIgnoresOtherObjects(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p"}}
	out, err := keepOnlyCredentialKeys(pod)
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	if out != pod {
		t.Error("a non-Secret object was replaced")
	}
}
