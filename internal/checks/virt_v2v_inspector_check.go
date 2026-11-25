package checks

import "strings"

// VirtV2VInspectorCheck runs virt-v2v-inspector and reports a Critical concern
// when the tool cannot inspect the guest.
type VirtV2VInspectorCheck struct{}

// NewVirtV2VInspectorCheck creates a new VirtV2VInspectorCheck instance.
func NewVirtV2VInspectorCheck() *VirtV2VInspectorCheck {
	return &VirtV2VInspectorCheck{}
}

// Run executes virt-v2v-inspector through the shared persistent inspector.
// sslVerify is deprecated and ignored by InspectWithVirtV2v - TLS config comes
// from Credentials - so an empty string is passed.
func (c *VirtV2VInspectorCheck) Run(params InspectionParams) CheckResult {
	_, err := params.Inspector.InspectWithVirtV2v(
		params.Ctx,
		params.VMMoref,
		params.SnapshotMoref,
		params.DiskInfo,
		"",
	)
	if err == nil {
		return CheckResult{Passed: true}
	}

	// internal/inspection's virt_v2v_inspector.go prefixes every error where
	// the tool actually ran and reported a verdict with one of these two
	// strings. Anything else (vSphere connection failure, TLS config error,
	// context cancellation, ...) means the check itself did not complete and
	// must not be reported as a finding about the VM.
	errStr := strings.ToLower(err.Error())
	if strings.Contains(errStr, "virt-v2v-inspector failed") || strings.Contains(errStr, "disk encryption detected") {
		return CheckResult{
			Passed: false,
			Concerns: []Concern{{
				ID:       "virt-v2v-dry-run-failed",
				Category: ConcernCategoryCritical,
				Label:    "virt-v2v-inspector could not inspect the guest",
				Message:  err.Error(),
			}},
		}
	}

	errMsg := err.Error()
	return CheckResult{
		Passed: false,
		Error:  &errMsg,
	}
}
