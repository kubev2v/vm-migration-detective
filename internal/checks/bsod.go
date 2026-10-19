package checks

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Velocidex/ordereddict"
	"github.com/kubev2v/vm-migration-detective/internal/inspection"
	"github.com/kubev2v/vm-migration-detective/pkg/checks"
	"www.velocidex.com/golang/evtx"
)

const (
	defaultTimeWindowDays = 30
	thresholdInformation  = 1
	thresholdWarning      = 2
	thresholdCritical     = 5
	maxRecentEvents       = 3
)

// Common Windows bug check codes (stop codes)
// Source: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-code-reference2
// Note: This table contains the most common codes seen in production environments.
// New codes are added by Microsoft periodically. Unknown codes are displayed as "Bug Check 0xXXXXXXXX"
// and logged for potential addition to this table.
var bugCheckNames = map[string]string{
	"0x00000001": "APC_INDEX_MISMATCH",
	"0x0000000a": "IRQL_NOT_LESS_OR_EQUAL",
	"0x0000001e": "KMODE_EXCEPTION_NOT_HANDLED",
	"0x00000024": "NTFS_FILE_SYSTEM",
	"0x0000003b": "SYSTEM_SERVICE_EXCEPTION",
	"0x0000003d": "INTERRUPT_EXCEPTION_NOT_HANDLED",
	"0x00000050": "PAGE_FAULT_IN_NONPAGED_AREA",
	"0x00000077": "KERNEL_STACK_INPAGE_ERROR",
	"0x0000007b": "INACCESSIBLE_BOOT_DEVICE",
	"0x0000007e": "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
	"0x0000007f": "UNEXPECTED_KERNEL_MODE_TRAP",
	"0x00000093": "INVALID_KERNEL_HANDLE",
	"0x0000009f": "DRIVER_POWER_STATE_FAILURE",
	"0x000000a5": "ACPI_BIOS_ERROR",
	"0x000000c2": "BAD_POOL_CALLER",
	"0x000000c5": "DRIVER_CORRUPTED_EXPOOL",
	"0x000000d1": "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
	"0x000000d5": "DRIVER_PAGE_FAULT_IN_FREED_SPECIAL_POOL",
	"0x000000d8": "DRIVER_USED_EXCESSIVE_PTES",
	"0x000000e1": "WORKER_THREAD_RETURNED_AT_BAD_IRQL",
	"0x000000ea": "THREAD_STUCK_IN_DEVICE_DRIVER",
	"0x000000f4": "CRITICAL_OBJECT_TERMINATION",
	"0x000000f7": "DRIVER_OVERRAN_STACK_BUFFER",
	"0x000000fe": "BUGCODE_USB_DRIVER",
	"0x00000124": "WHEA_UNCORRECTABLE_ERROR",
	"0x0000012b": "FAULTY_HARDWARE_CORRUPTED_PAGE",
	"0x0000013a": "KERNEL_MODE_HEAP_CORRUPTION",
	"0x0000013b": "PASSIVE_INTERRUPT_ERROR",
	"0x0000019c": "WIN32K_SECURITY_FAILURE",
	"0x000001a0": "WIN32K_CRITICAL_FAILURE",
}

type BSODEvent struct {
	Timestamp      time.Time
	EventID        int
	ProviderName   string
	BugCheckCode   string
	BugCheckString string
}

// BSODCheck validates Windows VMs for Blue Screen of Death (BSOD) events
type BSODCheck struct{}

func NewBSODCheck() *BSODCheck {
	return &BSODCheck{}
}

func (c *BSODCheck) Run(params InspectionParams) CheckResult {
	inspectionData, err := params.Inspector.InspectWithVirt(
		params.Ctx,
		params.VMMoref,
		params.SnapshotMoref,
		params.DiskInfo,
	)
	if err != nil {
		return errorResult(fmt.Errorf("failed to get inspection data: %w", err))
	}

	var rootDevice string
	isWindows := false
	for _, detectedOS := range inspectionData.Operatingsystems {
		if detectedOS.Name == "windows" {
			isWindows = true
			rootDevice = detectedOS.Root
			break
		}
	}

	if !isWindows {
		return CheckResult{
			CheckType: checks.CheckTypeNotApplicable,
			Passed:    true,
			Concerns:  nil,
		}
	}

	tempDir, err := os.MkdirTemp("", "bsod-check-*")
	if err != nil {
		return errorResult(fmt.Errorf("failed to create temp directory: %w", err))
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	guestPath := "/Windows/System32/winevt/Logs/System.evtx"
	if err := params.Inspector.ExtractFileFromGuest(
		params.Ctx,
		params.VMMoref,
		params.SnapshotMoref,
		params.DiskInfo,
		guestPath,
		tempDir,
		rootDevice,
	); err != nil {
		if errors.Is(err, inspection.ErrFileTooLarge) {
			const maxFileSizeMB = 100 // Must match persistent/inspection.go
			return CheckResult{
				CheckType: checks.CheckTypeBSOD,
				Passed:    false,
				Concerns: []Concern{{
					ID:       "bsod-log-too-large",
					Category: ConcernCategoryWarning,
					Label:    "Event log file too large to analyze",
					Message: fmt.Sprintf("Windows System event log exceeds %dMB size limit. "+
						"Enable Windows event log rotation to limit log file size. "+
						"See: Event Viewer → Windows Logs → System → Properties → Maximum log size. "+
						"Recommended: Set to 20-50MB with 'Overwrite events as needed' enabled.", maxFileSizeMB),
				}},
			}
		}
		return errorResult(fmt.Errorf("failed to extract event log: %w", err))
	}

	evtxPath := filepath.Join(tempDir, "System.evtx")
	evtxFile, err := os.Open(evtxPath)
	if err != nil {
		return errorResult(fmt.Errorf("failed to open event log: %w", err))
	}
	defer func() { _ = evtxFile.Close() }()

	bsodCount, recentEvents, corruptedChunks, totalChunks, err := parseBSODEvents(evtxFile, defaultTimeWindowDays)
	if err != nil {
		return errorResult(fmt.Errorf("failed to parse event log: %w", err))
	}

	concerns := createBSODConcern(bsodCount, recentEvents, corruptedChunks, totalChunks)
	passed := len(concerns) == 0

	return CheckResult{
		CheckType: checks.CheckTypeBSOD,
		Passed:    passed,
		Concerns:  concerns,
	}
}

// parseBSODEvents parses BSOD events from EVTX file
// Accepts io.ReadSeeker for testing with fixture data
func parseBSODEvents(evtxReader io.ReadSeeker, timeWindowDays int) (int, []BSODEvent, int, int, error) {
	var allEvents []BSODEvent
	cutoff := time.Now().UTC().AddDate(0, 0, -timeWindowDays)

	chunks, err := evtx.GetChunks(evtxReader)
	if err != nil {
		return 0, nil, 0, 0, fmt.Errorf("failed to get chunks: %w", err)
	}

	var failedChunks int
	totalChunks := len(chunks)
	for _, chunk := range chunks {
		records, err := chunk.Parse(0)
		if err != nil {
			failedChunks++
			continue
		}

		for _, record := range records {
			system, ok := getEventSystem(record.Event)
			if !ok {
				continue
			}

			eventID, ok := getEventID(system)
			if !ok {
				continue
			}

			providerName := getProviderName(system)
			if !isBSODEvent(eventID, providerName) {
				continue
			}

			eventTime := fileTimeToTime(record.Header.FileTime)
			if eventTime.IsZero() || eventTime.Before(cutoff) {
				continue
			}

			bugCheckCode := ""
			bugCheckString := ""
			if eventID == 1001 {
				bugCheckCode, bugCheckString = extractBugCheckInfo(record.Event)
				// Skip malformed Event 1001 without bug check code
				if bugCheckCode == "" {
					continue
				}
			}

			allEvents = append(allEvents, BSODEvent{
				Timestamp:      eventTime,
				EventID:        eventID,
				ProviderName:   providerName,
				BugCheckCode:   bugCheckCode,
				BugCheckString: bugCheckString,
			})
		}
	}

	// Deduplicate: prioritize Event 1001 (BugCheck) as canonical BSOD
	// Event 41/6008 within ±2 minutes of Event 1001 are considered part of same crash
	bsodCount, recentEvents := deduplicateBSODEvents(allEvents)

	return bsodCount, recentEvents, failedChunks, totalChunks, nil
}

// deduplicateBSODEvents removes duplicate events from same crash
// Event 1001 is canonical; Event 41/6008 within ±2min are clustered
func deduplicateBSODEvents(allEvents []BSODEvent) (int, []BSODEvent) {
	if len(allEvents) == 0 {
		return 0, nil
	}

	const dedupeWindow = 2 * time.Minute

	var bugCheckEvents []BSODEvent
	var otherEvents []BSODEvent

	for _, event := range allEvents {
		if event.EventID == 1001 {
			bugCheckEvents = append(bugCheckEvents, event)
		} else {
			otherEvents = append(otherEvents, event)
		}
	}

	sort.Slice(bugCheckEvents, func(i, j int) bool {
		return bugCheckEvents[i].Timestamp.Before(bugCheckEvents[j].Timestamp)
	})

	var uniqueOtherEvents []BSODEvent

	for _, event := range otherEvents {
		isDuplicate := false

		idx := sort.Search(len(bugCheckEvents), func(i int) bool {
			return bugCheckEvents[i].Timestamp.After(event.Timestamp)
		})

		// Check adjacent events (only candidates within time window)
		for _, checkIdx := range []int{idx - 1, idx} {
			if checkIdx >= 0 && checkIdx < len(bugCheckEvents) {
				timeDiff := event.Timestamp.Sub(bugCheckEvents[checkIdx].Timestamp)
				if timeDiff < 0 {
					timeDiff = -timeDiff
				}
				if timeDiff <= dedupeWindow {
					isDuplicate = true
					break
				}
			}
		}

		if !isDuplicate {
			uniqueOtherEvents = append(uniqueOtherEvents, event)
		}
	}

	// Second-level deduplication: cluster Event 41/6008 by timestamp
	// Events within 2min = same crash, pick most representative (prefer Event 41)
	groupedOtherEvents := groupEventsByTime(uniqueOtherEvents, dedupeWindow)

	// Total unique crashes = BugCheck events + clustered other events
	bsodCount := len(bugCheckEvents) + len(groupedOtherEvents)

	// Combine all unique events for recent events display
	var uniqueEvents []BSODEvent
	uniqueEvents = append(uniqueEvents, bugCheckEvents...)
	uniqueEvents = append(uniqueEvents, groupedOtherEvents...)

	// Sort by timestamp descending (most recent first)
	sort.Slice(uniqueEvents, func(i, j int) bool {
		return uniqueEvents[i].Timestamp.After(uniqueEvents[j].Timestamp)
	})

	// Return top N recent events
	recentEvents := uniqueEvents
	if len(recentEvents) > maxRecentEvents {
		recentEvents = recentEvents[:maxRecentEvents]
	}

	return bsodCount, recentEvents
}

// groupEventsByTime groups events within timeWindow (same crash), returns one per group
func groupEventsByTime(events []BSODEvent, timeWindow time.Duration) []BSODEvent {
	if len(events) == 0 {
		return nil
	}

	// Sort events by timestamp (ascending)
	sortedEvents := make([]BSODEvent, len(events))
	copy(sortedEvents, events)
	sort.Slice(sortedEvents, func(i, j int) bool {
		return sortedEvents[i].Timestamp.Before(sortedEvents[j].Timestamp)
	})

	var crashGroups [][]BSODEvent
	var currentCrashGroup []BSODEvent

	for _, event := range sortedEvents {
		if len(currentCrashGroup) == 0 {
			currentCrashGroup = append(currentCrashGroup, event)
		} else {
			crashStart := currentCrashGroup[0].Timestamp
			timeDiff := event.Timestamp.Sub(crashStart)
			if timeDiff < 0 {
				timeDiff = -timeDiff
			}

			if timeDiff <= timeWindow {
				currentCrashGroup = append(currentCrashGroup, event)
			} else {
				crashGroups = append(crashGroups, currentCrashGroup)
				currentCrashGroup = []BSODEvent{event}
			}
		}
	}

	if len(currentCrashGroup) > 0 {
		crashGroups = append(crashGroups, currentCrashGroup)
	}

	// Pick one representative event per crash (prefer Event 41 over 6008)
	var representatives []BSODEvent
	for _, crashGroup := range crashGroups {
		representative := crashGroup[0]
		for _, event := range crashGroup {
			if event.EventID == 41 {
				representative = event
				break
			}
		}
		representatives = append(representatives, representative)
	}

	return representatives
}

func getEventSystem(event interface{}) (*ordereddict.Dict, bool) {
	eventMap, ok := event.(*ordereddict.Dict)
	if !ok {
		return nil, false
	}

	if system, ok := ordereddict.GetMap(eventMap, "System"); ok {
		return system, true
	}

	eventNode, ok := ordereddict.GetMap(eventMap, "Event")
	if !ok {
		return nil, false
	}

	return ordereddict.GetMap(eventNode, "System")
}

func getEventID(system *ordereddict.Dict) (int, bool) {
	if eventID, ok := ordereddict.GetInt(system, "EventID"); ok {
		return eventID, true
	}
	if eventID, ok := ordereddict.GetInt(system, "EventID.Value"); ok {
		return eventID, true
	}

	eventIDMap, ok := ordereddict.GetMap(system, "EventID")
	if !ok {
		return 0, false
	}

	if eventID, ok := ordereddict.GetInt(eventIDMap, "Value"); ok {
		return eventID, true
	}
	if eventID, ok := ordereddict.GetInt(eventIDMap, "#text"); ok {
		return eventID, true
	}
	return 0, false
}

func getProviderName(system *ordereddict.Dict) string {
	if providerName, ok := ordereddict.GetString(system, "Provider.Name"); ok {
		return providerName
	}
	if provider, ok := ordereddict.GetMap(system, "Provider"); ok {
		providerName, _ := ordereddict.GetString(provider, "Name")
		return providerName
	}
	return ""
}

func isBSODEvent(eventID int, providerName string) bool {
	switch eventID {
	case 41:
		return providerName == "Microsoft-Windows-Kernel-Power" || providerName == "Kernel-Power"
	case 1001:
		return providerName == "BugCheck" || providerName == "Microsoft-Windows-WER-SystemErrorReporting"
	case 6008:
		return providerName == "EventLog"
	default:
		return false
	}
}

func fileTimeToTime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}

	const (
		windowsTicksPerSecond = 10_000_000
		windowsToUnixEpoch    = 11644473600
	)

	secs := int64(ft/windowsTicksPerSecond) - windowsToUnixEpoch
	nsec := int64(ft%windowsTicksPerSecond) * 100
	return time.Unix(secs, nsec).UTC()
}

// extractBugCheckInfo extracts bug check code from Event 1001 (BugCheck) event data
func extractBugCheckInfo(event interface{}) (string, string) {
	eventMap, ok := event.(*ordereddict.Dict)
	if !ok {
		return "", ""
	}

	// Navigate to EventData section
	eventNode, ok := ordereddict.GetMap(eventMap, "Event")
	if !ok {
		// Try direct access
		eventNode = eventMap
	}

	eventData, ok := ordereddict.GetMap(eventNode, "EventData")
	if !ok {
		// Try UserData as alternative
		eventData, ok = ordereddict.GetMap(eventNode, "UserData")
		if !ok {
			return "", ""
		}
	}

	// Event 1001 from Microsoft-Windows-WER-SystemErrorReporting has structure:
	// EventData or UserData contains multiple Data elements with Name attributes
	// We need to find Data elements with Name="param1" (bug check code), "param2" (param1 value), etc.

	// Try to get bug check code from param1
	bugCheckCode := ""
	bugCheckString := ""

	// Method 1: Try BugcheckCode/BugcheckString fields directly
	bugCheckCode, _ = ordereddict.GetString(eventData, "BugcheckCode")
	bugCheckString, _ = ordereddict.GetString(eventData, "BugcheckString")

	// Method 2: Try param1/param2 fields (common in WER events)
	if bugCheckCode == "" {
		bugCheckCode, _ = ordereddict.GetString(eventData, "param1")
	}
	if bugCheckString == "" {
		bugCheckString, _ = ordereddict.GetString(eventData, "param2")
	}

	// Method 3: Try to iterate Data array elements
	if bugCheckCode == "" {
		// EventData might contain array of Data elements
		if dataArray, ok := eventData.Get("Data"); ok {
			// Try as array
			if arr, ok := dataArray.([]interface{}); ok && len(arr) > 0 {
				// First element might be bug check code
				if firstData, ok := arr[0].(*ordereddict.Dict); ok {
					bugCheckCode, _ = ordereddict.GetString(firstData, "#text")
				}
			}
		}
	}

	return bugCheckCode, bugCheckString
}

// sanitizeString removes control characters and limits length to prevent malformed EVTX
// data from breaking output formatting
func sanitizeString(s string, maxLen int) string {
	// Remove control characters (0x00-0x1F except tab/newline, and 0x7F-0x9F)
	var result strings.Builder
	result.Grow(len(s))

	for _, r := range s {
		// Keep printable ASCII and normal Unicode, skip control chars
		if r >= 0x20 && r != 0x7F && (r < 0x80 || r > 0x9F) {
			result.WriteRune(r)
		}
	}

	sanitized := result.String()
	if len(sanitized) > maxLen {
		return sanitized[:maxLen] + "..."
	}
	return sanitized
}

// extractStopCode extracts the stop code from bug check string
// Input: "0x000000d1 (0xffffbd8d1d7b3010, 0x0000000000000002, ...) - C:\Windows\MEMORY.DMP"
// Output: "0x000000d1"
func extractStopCode(bugCheckCode string) string {
	// Sanitize input to prevent control characters from breaking output
	bugCheckCode = sanitizeString(bugCheckCode, 200)

	// Find first space or opening parenthesis
	code := bugCheckCode
	if idx := strings.Index(code, " "); idx != -1 {
		code = code[:idx]
	}
	if idx := strings.Index(code, "("); idx != -1 {
		code = code[:idx]
	}
	return strings.TrimSpace(code)
}

// getBugCheckName returns the human-readable name for a bug check code
func getBugCheckName(code string) string {
	// Normalize code to lowercase for lookup
	normalizedCode := strings.ToLower(strings.TrimSpace(code))

	// Handle common formats: 0xD1, 0x000000d1, d1, etc.
	// Normalize to 0x00000000 format (8 hex digits)
	normalizedCode = strings.TrimPrefix(normalizedCode, "0x")

	// Pad to 8 digits
	if len(normalizedCode) < 8 {
		normalizedCode = strings.Repeat("0", 8-len(normalizedCode)) + normalizedCode
	}

	// Look up with 0x prefix
	lookupKey := "0x" + normalizedCode
	if name, ok := bugCheckNames[lookupKey]; ok {
		return name
	}

	return "" // Unknown bug check code
}

func createBSODConcern(bsodCount int, recentEvents []BSODEvent, corruptedChunks, totalChunks int) []Concern {
	if bsodCount == 0 {
		return nil
	}

	var severity ConcernCategory
	switch {
	case bsodCount >= thresholdCritical:
		severity = ConcernCategoryCritical
	case bsodCount >= thresholdWarning:
		severity = ConcernCategoryWarning
	default:
		severity = ConcernCategoryInformation
	}

	// Build details section with recent events
	details := fmt.Sprintf("Found %d BSOD events in the last %d days.\n\n", bsodCount, defaultTimeWindowDays)

	// Add corruption warning if chunks failed to parse
	if corruptedChunks > 0 {
		details += fmt.Sprintf("⚠️  WARNING: %d/%d event log chunks failed to parse (possibly corrupted after crashes).\n", corruptedChunks, totalChunks)
		details += "BSOD count may be underreported. Consider manual review of Windows Event Viewer.\n\n"
	}

	if len(recentEvents) > 0 {
		details += "Recent BSODs:\n"
		for _, event := range recentEvents {
			eventDesc := fmt.Sprintf("- %s [Event %d]: ", event.Timestamp.Format("2006-01-02 15:04:05"), event.EventID)

			switch event.EventID {
			case 1001: // BugCheck with code
				if event.BugCheckCode != "" && event.BugCheckCode != "Unknown" {
					// Extract just the stop code (e.g., "0x000000d1" from full string)
					stopCode := extractStopCode(event.BugCheckCode)
					bugCheckName := getBugCheckName(stopCode)

					if bugCheckName != "" {
						// Format: DRIVER_IRQL_NOT_LESS_OR_EQUAL (0x000000D1)
						eventDesc += fmt.Sprintf("%s (%s)", bugCheckName, strings.ToUpper(stopCode))
					} else {
						// Unknown code - show just the code
						// Note: If you see this message, the bug check code may be new or uncommon.
						// Check https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-code-reference2
						// and consider adding it to the bugCheckNames table in bsod.go
						eventDesc += fmt.Sprintf("Bug Check %s", strings.ToUpper(stopCode))
					}
				} else {
					eventDesc += "System Error Report (BugCheck)"
				}
			case 41: // Kernel-Power
				eventDesc += "Unexpected shutdown (Kernel-Power critical error)"
			case 6008: // EventLog
				eventDesc += "Unexpected system shutdown"
			}

			details += eventDesc + "\n"
		}
		details += "\nNote: Review Windows Event Viewer for complete bug check codes and parameters."
	}

	return []Concern{{
		ID:       "bsod-detected",
		Category: severity,
		Label:    fmt.Sprintf("%d BSOD events detected", bsodCount),
		Message: fmt.Sprintf(
			"VM has experienced %d BSOD events in the last %d days. "+
				"Review bug check codes to identify hardware or driver issues. "+
				"Consider addressing stability problems before migration.",
			bsodCount,
			defaultTimeWindowDays,
		),
		Details: details,
	}}
}

func errorResult(err error) CheckResult {
	errMsg := err.Error()
	return CheckResult{
		CheckType: checks.CheckTypeBSOD,
		Passed:    false,
		Concerns:  nil,
		Error:     &errMsg,
	}
}
