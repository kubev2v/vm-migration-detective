package checks

// VirtV2VInspectorCheck runs virt-v2v-inspector and reports a Critical concern
// when the tool cannot inspect the guest.
type VirtV2VInspectorCheck struct{}

// NewVirtV2VInspectorCheck creates a new VirtV2VInspectorCheck instance.
func NewVirtV2VInspectorCheck() *VirtV2VInspectorCheck {
	return &VirtV2VInspectorCheck{}
}

// Run executes virt-v2v-inspector through the shared persistent inspector.
func (c *VirtV2VInspectorCheck) Run(params InspectionParams) CheckResult {
	_, err := params.Inspector.InspectWithVirtV2v(
		params.Ctx,
		params.VMMoref,
		params.SnapshotMoref,
		params.DiskInfo,
	)
	if err == nil {
		return CheckResult{Passed: true}
	}

	return CheckResult{
		Passed: false,
		Concerns: []Concern{{
			ID:       "virt-v2v-inspector-failed",
			Category: ConcernCategoryCritical,
			Label:    "virt-v2v-inspector could not inspect the guest",
			Message:  err.Error(),
		}},
	}
}
