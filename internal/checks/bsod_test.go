package checks

import (
	"context"
	"testing"
	"time"

	"github.com/kubev2v/vm-migration-detective/internal/persistent"
	"github.com/kubev2v/vm-migration-detective/pkg/checks"
	"github.com/kubev2v/vm-migration-detective/pkg/types"
)

// mockInspector is a mock implementation of InspectorInterface for testing
type mockInspector struct {
	inspectionData *types.VirtInspectorXML
	err            error
}

func (m *mockInspector) InspectWithVirt(
	ctx context.Context,
	vmMoref string,
	snapshotMoref string,
	diskInfo *types.SnapshotDiskInfo,
) (*types.VirtInspectorXML, error) {
	return m.inspectionData, m.err
}

func (m *mockInspector) InspectWithVirtV2v(
	ctx context.Context,
	vmMoref string,
	snapshotMoref string,
	diskInfo *types.SnapshotDiskInfo,
	sslVerify string,
) (*types.VirtV2VInspectorXML, error) {
	return nil, nil
}

func (m *mockInspector) GetDB() persistent.DB {
	return nil
}

func (m *mockInspector) ExtractFileFromGuest(
	ctx context.Context,
	vmMoref string,
	snapshotMoref string,
	diskInfo *types.SnapshotDiskInfo,
	guestPath string,
	destDir string,
	rootDevice string,
) error {
	return nil
}

// TestBSODCheck_NonWindows_Skip verifies that BSOD check returns empty CheckType for non-Windows VMs
func TestBSODCheck_NonWindows_Skip(t *testing.T) {
	check := NewBSODCheck()

	// Create mock inspector with Linux VM data
	mockInsp := &mockInspector{
		inspectionData: &types.VirtInspectorXML{
			Operatingsystems: []types.OS{
				{
					Name:   "linux",
					Distro: "rhel",
				},
			},
		},
		err: nil,
	}

	params := InspectionParams{
		Ctx:       context.Background(),
		Inspector: mockInsp,
	}

	result := check.Run(params)

	// Should pass for non-Windows VMs
	if !result.Passed {
		t.Errorf("Expected BSOD check to pass for Linux VM, got passed=%v", result.Passed)
	}

	// Should have no concerns
	if len(result.Concerns) != 0 {
		t.Errorf("Expected 0 concerns for Linux VM, got %d", len(result.Concerns))
	}

	// Should have no error
	if result.Error != nil {
		t.Errorf("Expected no error for Linux VM, got error=%v", *result.Error)
	}

	// Should return CheckTypeNotApplicable to signal exclusion from results
	if result.CheckType != checks.CheckTypeNotApplicable {
		t.Errorf("Expected CheckTypeNotApplicable for Linux VM (to exclude from results), got %s", result.CheckType)
	}
}

// TestFileTimeToTime verifies Windows FILETIME conversion
func TestFileTimeToTime(t *testing.T) {
	t.Parallel()

	got := fileTimeToTime(116444736000000000)
	want := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("fileTimeToTime() = %v, want %v", got, want)
	}

	if !fileTimeToTime(0).IsZero() {
		t.Fatal("expected zero FILETIME to map to zero time")
	}
}

// TestCreateBSODConcern_Thresholds verifies severity tier application
func TestCreateBSODConcern_Thresholds(t *testing.T) {
	tests := []struct {
		name         string
		bsodCount    int
		wantConcerns int
		wantSeverity ConcernCategory
	}{
		{
			name:         "0 BSODs",
			bsodCount:    0,
			wantConcerns: 0,
		},
		{
			name:         "1 BSOD - Information",
			bsodCount:    1,
			wantConcerns: 1,
			wantSeverity: ConcernCategoryInformation,
		},
		{
			name:         "3 BSODs - Warning",
			bsodCount:    3,
			wantConcerns: 1,
			wantSeverity: ConcernCategoryWarning,
		},
		{
			name:         "6 BSODs - Critical",
			bsodCount:    6,
			wantConcerns: 1,
			wantSeverity: ConcernCategoryCritical,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			concerns := createBSODConcern(tt.bsodCount, nil, 0, 0)

			if len(concerns) != tt.wantConcerns {
				t.Errorf("Expected %d concerns, got %d", tt.wantConcerns, len(concerns))
			}

			if tt.wantConcerns > 0 {
				if concerns[0].Category != tt.wantSeverity {
					t.Errorf("Expected severity %s, got %s", tt.wantSeverity, concerns[0].Category)
				}
			}
		})
	}
}

// TestDeduplicateBSODEvents verifies BSOD deduplication logic
func TestDeduplicateBSODEvents(t *testing.T) {
	t.Parallel()

	baseTime := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name        string
		events      []BSODEvent
		wantCount   int
		wantRecent  int
		wantFirstID int // EventID of first recent event
	}{
		{
			name:       "empty input",
			events:     []BSODEvent{},
			wantCount:  0,
			wantRecent: 0,
		},
		{
			name: "single Event 1001",
			events: []BSODEvent{
				{Timestamp: baseTime, EventID: 1001, BugCheckCode: "0xD1"},
			},
			wantCount:   1,
			wantRecent:  1,
			wantFirstID: 1001,
		},
		{
			name: "Event 41 within 2min of Event 1001 - deduplicated",
			events: []BSODEvent{
				{Timestamp: baseTime, EventID: 1001, BugCheckCode: "0xD1"},
				{Timestamp: baseTime.Add(1 * time.Minute), EventID: 41},
			},
			wantCount:   1, // Clustered as one crash
			wantRecent:  1,
			wantFirstID: 1001,
		},
		{
			name: "Event 41 beyond 2min window - separate crash",
			events: []BSODEvent{
				{Timestamp: baseTime, EventID: 1001, BugCheckCode: "0xD1"},
				{Timestamp: baseTime.Add(3 * time.Minute), EventID: 41},
			},
			wantCount:   2, // Two separate crashes
			wantRecent:  2,
			wantFirstID: 41, // Most recent first (sorted desc)
		},
		{
			name: "multiple Event 41/6008 within same 2min window - grouped",
			events: []BSODEvent{
				{Timestamp: baseTime, EventID: 41},
				{Timestamp: baseTime.Add(30 * time.Second), EventID: 6008},
				{Timestamp: baseTime.Add(1 * time.Minute), EventID: 6008},
			},
			wantCount:   1, // All grouped as one crash
			wantRecent:  1,
			wantFirstID: 41, // Prefer Event 41 as representative
		},
		{
			name: "overlapping time windows",
			events: []BSODEvent{
				{Timestamp: baseTime, EventID: 41},
				{Timestamp: baseTime.Add(90 * time.Second), EventID: 41},
				{Timestamp: baseTime.Add(3 * time.Minute), EventID: 41},
			},
			wantCount:   2, // Events 1&2 grouped, Event 3 separate
			wantRecent:  2,
			wantFirstID: 41,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCount, gotRecent := deduplicateBSODEvents(tt.events)

			if gotCount != tt.wantCount {
				t.Errorf("count = %d, want %d", gotCount, tt.wantCount)
			}

			if len(gotRecent) != tt.wantRecent {
				t.Errorf("recent count = %d, want %d", len(gotRecent), tt.wantRecent)
			}

			if tt.wantRecent > 0 && gotRecent[0].EventID != tt.wantFirstID {
				t.Errorf("first recent EventID = %d, want %d", gotRecent[0].EventID, tt.wantFirstID)
			}
		})
	}
}

// TestGroupEventsByTime verifies crash grouping logic
func TestGroupEventsByTime(t *testing.T) {
	t.Parallel()

	baseTime := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	window := 2 * time.Minute

	tests := []struct {
		name        string
		events      []BSODEvent
		wantGroups  int
		wantFirstID int // EventID of first representative
	}{
		{
			name:       "empty input",
			events:     []BSODEvent{},
			wantGroups: 0,
		},
		{
			name: "single event",
			events: []BSODEvent{
				{Timestamp: baseTime, EventID: 41},
			},
			wantGroups:  1,
			wantFirstID: 41,
		},
		{
			name: "two events within window - one group",
			events: []BSODEvent{
				{Timestamp: baseTime, EventID: 6008},
				{Timestamp: baseTime.Add(1 * time.Minute), EventID: 41},
			},
			wantGroups:  1,
			wantFirstID: 41, // Prefer Event 41
		},
		{
			name: "events outside window - separate groups",
			events: []BSODEvent{
				{Timestamp: baseTime, EventID: 41},
				{Timestamp: baseTime.Add(3 * time.Minute), EventID: 41},
			},
			wantGroups:  2,
			wantFirstID: 41,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := groupEventsByTime(tt.events, window)

			if len(got) != tt.wantGroups {
				t.Errorf("groups = %d, want %d", len(got), tt.wantGroups)
			}

			if tt.wantGroups > 0 && got[0].EventID != tt.wantFirstID {
				t.Errorf("first representative EventID = %d, want %d", got[0].EventID, tt.wantFirstID)
			}
		})
	}
}

// TestExtractStopCode verifies bug check code extraction
func TestExtractStopCode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  string
	}{
		{
			input: "0x000000d1 (0xffffbd8d1d7b3010, 0x0000000000000002, ...)",
			want:  "0x000000d1",
		},
		{
			input: "0xD1 (params)",
			want:  "0xD1",
		},
		{
			input: "0x0000007E",
			want:  "0x0000007E",
		},
		{
			input: "",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := extractStopCode(tt.input)
			if got != tt.want {
				t.Errorf("extractStopCode(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestGetBugCheckName verifies bug check name lookup
func TestGetBugCheckName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		code string
		want string
	}{
		{
			code: "0x000000d1",
			want: "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
		},
		{
			code: "0xD1", // Short form
			want: "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
		},
		{
			code: "d1", // No 0x prefix
			want: "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
		},
		{
			code: "0x0000007E",
			want: "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
		},
		{
			code: "0xFFFFFFFF", // Unknown code
			want: "",
		},
		{
			code: "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			got := getBugCheckName(tt.code)
			if got != tt.want {
				t.Errorf("getBugCheckName(%q) = %q, want %q", tt.code, got, tt.want)
			}
		})
	}
}

// TestSanitizeString verifies control character stripping
func TestSanitizeString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  string
		maxLen int
		want   string
	}{
		{
			name:   "clean string",
			input:  "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
			maxLen: 100,
			want:   "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
		},
		{
			name:   "control characters removed",
			input:  "test\x00\x01\x1Fstring",
			maxLen: 100,
			want:   "teststring",
		},
		{
			name:   "truncated at maxLen",
			input:  "verylongstring",
			maxLen: 5,
			want:   "veryl...",
		},
		{
			name:   "DEL character (0x7F) removed",
			input:  "test\x7Fstring",
			maxLen: 100,
			want:   "teststring",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeString(tt.input, tt.maxLen)
			if got != tt.want {
				t.Errorf("sanitizeString(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
			}
		})
	}
}
