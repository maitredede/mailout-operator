// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Damien Daly.

package controller

import (
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// setCondition records a condition, leaving LastTransitionTime alone when
// nothing actually changed — otherwise every reconciliation would look like a
// state change.
func setCondition(conditions *[]metav1.Condition, conditionType string,
	status metav1.ConditionStatus, reason, message string, generation int64) {
	meta.SetStatusCondition(conditions, metav1.Condition{
		Type:               conditionType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: generation,
	})
}
