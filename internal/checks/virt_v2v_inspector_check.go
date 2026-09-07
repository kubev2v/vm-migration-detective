package checks

// VirtV2VInspectorCheck runs virt-v2v-inspector and reports a Critical concern
// when the tool exits with a non-zero return code.
type VirtV2VInspectorCheck struct{}

// NewVirtV2VInspectorCheck creates a new VirtV2VInspectorCheck instance.
func NewVirtV2VInspectorCheck() *VirtV2VInspectorCheck {
	return &VirtV2VInspectorCheck{}
}

// Run executes virt-v2v-inspector via the shared inspector and returns a
// Critical concern when the tool fails (non-zero exit code).
func (c *VirtV2VInspectorCheck) Run(params InspectionParams) CheckResult {
	_, err := params.Inspector.InspectWithVirtV2v(
		params.Ctx,
		params.VMMoref,
		params.SnapshotMoref,
		params.DiskInfo,
	)
	if err != nil {
		return CheckResult{
			Passed: false,
			Concerns: []Concern{
				{
					ID:       "virt-v2v-inspector-failed",
					Category: ConcernCategoryCritical,
					Label:    "virt-v2v-inspector returned a non-zero exit code",
					Message:  err.Error(),
				},
			},
		}
	}

	return CheckResult{Passed: true}
}
