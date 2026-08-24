# vm-migration-detective

Go library for VM detection and validation before migration.

## Overview

This library provides a comprehensive API for inspecting and validating VMware virtual machines before migration. It detects potential migration blockers, validates configurations, and gathers VM information using virt-inspector and virt-v2v-inspector with VDDK integration.

## Features

- **VM Detection & Validation**: Run automated checks to detect migration concerns
- **Persistent Caching**: Optional database persistence for inspection results
- **Concurrent Safety**: Efficient handling of concurrent requests for the same VM
- **Memory Caching**: Fast in-memory cache with automatic population from DB
- **Flexible Configuration**: Customizable paths, timeouts, and logging
- **Type-Safe API**: Well-defined public types for all operations

## Quick Start

```go
import (
    "github.com/kubev2v/vm-migration-detective/pkg/vmdetect"
)

// Create detector
detector, err := vmdetect.NewDetector(vmdetect.DetectorConfig{
    Credentials: vmdetect.Credentials{
        VCenterURL:    "https://vcenter.example.com",
        Username:      "user@vsphere.local",
        Password:      "password",
        TLSThumbprint: "AA:BB:CC:...", // See TLS Configuration section
    },
    VDDKLibDir: "/opt/vmware-vix-disklib",
    Logger:     logger,  // *logrus.Logger (optional)
    DB:         db,      // vmdetect.DB implementation (optional)
})

// Run detection
result, err := detector.Detect(vmdetect.DetectParams{
    Ctx:           ctx,
    VMMoref:       "vm-123",
    SnapshotMoref: "snapshot-456",
})

// Check results
if !result.Passed {
    for _, concern := range result.AllConcerns {
        fmt.Printf("[%s] %s: %s\n", concern.Category, concern.Label, concern.Message)
    }
}
```

## TLS Configuration

**⚠️  DEPRECATION NOTICE:** Starting in v1.0.0, TLS configuration will be required. Configure TLS verification now to avoid breaking changes in future releases.

For security, vm-migration-detective supports TLS verification for all vCenter connections. You can configure TLS verification in three ways:

### Option 1: CA Certificate Bundle (Recommended for Production)

Use a CA certificate bundle to verify the vCenter certificate chain:

```go
detector, err := vmdetect.NewDetector(vmdetect.DetectorConfig{
    Credentials: vmdetect.Credentials{
        VCenterURL: "https://vcenter.example.com",
        Username:   "user@vsphere.local",
        Password:   "password",
        TLSCACert:  "/etc/ssl/certs/vcenter-ca.crt",
    },
    VDDKLibDir: "/opt/vmware-vix-disklib",
})
```

### Option 2: Certificate Thumbprint Pinning

Pin to a specific vCenter certificate using its SHA-1 thumbprint:

```go
detector, err := vmdetect.NewDetector(vmdetect.DetectorConfig{
    Credentials: vmdetect.Credentials{
        VCenterURL:     "https://vcenter.example.com",
        Username:       "user@vsphere.local",
        Password:       "password",
        TLSThumbprint:  "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD",
    },
    VDDKLibDir: "/opt/vmware-vix-disklib",
})
```

**Getting the vCenter thumbprint:**

```bash
openssl s_client -connect vcenter.example.com:443 < /dev/null 2>/dev/null | \
  openssl x509 -fingerprint -sha1 -noout -in /dev/stdin | \
  cut -d= -f2
```

### Option 3: Insecure Mode (Testing Only)

**WARNING:** Only use this for testing/development. Your vCenter credentials are vulnerable to MITM attacks.

```go
detector, err := vmdetect.NewDetector(vmdetect.DetectorConfig{
    Credentials: vmdetect.Credentials{
        VCenterURL:  "https://vcenter.example.com",
        Username:    "user@vsphere.local",
        Password:    "password",
        TLSInsecure: true, // Explicitly disable TLS verification
    },
    VDDKLibDir: "/opt/vmware-vix-disklib",
})
```

### Backward Compatibility (Deprecated)

If no TLS configuration is provided, connections will default to insecure mode with **LOUD deprecation warnings**:

```
⚠️  ════════════════════════════════════════════════════════════════════════
⚠️  SECURITY WARNING: TLS verification is DISABLED for vCenter connections!
⚠️  ════════════════════════════════════════════════════════════════════════
⚠️  
⚠️  This configuration is DEPRECATED and will be REQUIRED in v1.0.0
⚠️  Your vCenter credentials are vulnerable to MITM attacks.
⚠️  
⚠️  Please configure TLS verification in Credentials:
⚠️    • TLSCACert: "/path/to/ca-bundle.crt" (recommended for production)
⚠️    • TLSThumbprint: "AA:BB:CC:..." (certificate pinning)
⚠️    • TLSInsecure: true (explicit opt-in for testing only)
⚠️  
⚠️  Documentation: https://github.com/kubev2v/vm-migration-detective#tls-configuration
⚠️  ════════════════════════════════════════════════════════════════════════
```

This backward-compatible mode will be removed in v1.0.0. **Configure TLS verification now.**

## API Structure

### Public API (`pkg/`)

**pkg/vmdetect** - Main detection API
- `Detector`: Primary interface for VM detection operations
- `DetectorConfig`: Configuration for creating a detector
- `DetectParams`: Parameters for detection operations
- `DetectResult`: Detection results with checks and concerns
- `CheckType`: Available validation checks (fstab, disk-access, etc.)

**pkg/types** - Core data types
- `Credentials`: vCenter access credentials
- `CacheKey`: VM+snapshot unique identifier with hash function
- `DB`: Interface for persistent storage of inspection data
- `SnapshotDiskInfo`: VM snapshot disk information for VDDK
- `VirtInspectorXML`: virt-inspector output structures
- `VirtV2VInspectorXML`: virt-v2v-inspector output structures

**pkg/checks** - Validation concern types
- `Concern`: A detected migration concern
- `ConcernCategory`: Severity level (Critical, Warning, Information, Advisory, Error)

### Internal Implementation (`internal/`)

- **internal/inspection**: VM inspection engines (virt-inspector, virt-v2v-inspector)
- **internal/persistent**: Caching, inspector lifecycle, and concurrent request handling
- **internal/checks**: Validation check implementations
- **internal/vddk**: VDDK library integration and configuration

## Usage Examples

### Basic Detection (All Checks)

```go
detector, err := vmdetect.NewDetector(vmdetect.DetectorConfig{
    Credentials: vmdetect.Credentials{
        VCenterURL:    "https://vcenter.example.com",
        Username:      "admin@vsphere.local",
        Password:      "password",
        TLSCACert:     "/etc/ssl/certs/vcenter-ca.crt", // Recommended
    },
    VDDKLibDir: "/opt/vmware-vix-disklib",
})
if err != nil {
    log.Fatal(err)
}

result, err := detector.Detect(vmdetect.DetectParams{
    Ctx:           context.Background(),
    VMMoref:       "vm-123",
    SnapshotMoref: "snapshot-456",
})
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Passed: %v\n", result.Passed)
fmt.Printf("Total concerns: %d\n", len(result.AllConcerns))
```

### Run Specific Checks

```go
// Only run fstab check
result, err := detector.Detect(params, vmdetect.CheckTypeFstab)

// Run multiple specific checks
result, err := detector.Detect(params,
    vmdetect.CheckTypeFstab,
    vmdetect.CheckTypeDiskAccess,
)
```

### Implement Persistent Storage

```go
type MyDB struct {
    db *gorm.DB
}

func (d *MyDB) GetVirtInspectorXML(ctx context.Context, key vmdetect.CacheKey) (*types.VirtInspectorXML, error) {
    var record InspectionRecord
    err := d.db.Where("cache_key = ?", key.Hash()).First(&record).Error
    if err == gorm.ErrRecordNotFound {
        return nil, nil
    }
    if err != nil {
        return nil, err
    }

    var data types.VirtInspectorXML
    if err := json.Unmarshal([]byte(record.DataJSON), &data); err != nil {
        return nil, err
    }
    return &data, nil
}

func (d *MyDB) SetVirtInspectorXML(ctx context.Context, key vmdetect.CacheKey, data *types.VirtInspectorXML) error {
    jsonData, err := json.Marshal(data)
    if err != nil {
        return err
    }

    record := InspectionRecord{
        VMMoref:       key.VMMoref,
        SnapshotMoref: key.SnapshotMoref,
        CacheKey:      key.Hash(),
        DataJSON:      string(jsonData),
    }

    return d.db.Where("cache_key = ?", key.Hash()).
        Assign(record).FirstOrCreate(&record).Error
}

// Implement GetVirtV2VInspectorXML and SetVirtV2VInspectorXML similarly

detector, err := vmdetect.NewDetector(vmdetect.DetectorConfig{
    Credentials: credentials,
    VDDKLibDir:  "/opt/vmware-vix-disklib",
    DB:          &MyDB{db: gormDB},
})
```

### Custom Configuration

```go
virtInspectorPath := "/usr/local/bin/virt-inspector"
virtV2vInspectorPath := "/usr/local/bin/virt-v2v-inspector"
timeout := 45 * time.Minute

detector, err := vmdetect.NewDetector(vmdetect.DetectorConfig{
    Credentials:          credentials,
    VDDKLibDir:           "/opt/vmware-vix-disklib",
    VirtInspectorPath:    &virtInspectorPath,
    VirtV2vInspectorPath: &virtV2vInspectorPath,
    Timeout:              &timeout,
    Logger:               logger,
    DB:                   db,
})
```

## Available Checks

- **CheckTypeFstab**: Validates /etc/fstab entries for migration compatibility
- **CheckTypeDiskAccess**: Verifies disk accessibility (detects encrypted disks)

## Development

### Makefile Targets

- `make validate-all`: Run all validations (lint, format check, tidy check)
- `make lint`: Run golangci-lint
- `make format`: Format code with goimports
- `make check-format`: Check if code formatting is correct
- `make tidy`: Tidy go modules
- `make tidy-check`: Check if go.mod and go.sum are tidy
- `make verify`: Verify the code compiles
- `make clean`: Clean build artifacts and downloaded tools

## Requirements

- Go 1.24.0 or later
- libguestfs tools (virt-inspector)
- virt-v2v tools (virt-v2v-inspector)
- VMware VDDK library (required)
- NBDKit with VDDK plugin

## How It Works

1. **Inspector Creation**: Creates managed inspector instance with VDDK configuration
2. **Multi-layer Caching**:
   - Memory cache (fastest)
   - Database cache (persistent, if configured)
   - Inflight request deduplication (prevents duplicate concurrent work)
3. **Inspection**: Runs virt-inspector or virt-v2v-inspector via VDDK
4. **Validation**: Executes configured checks against inspection results
5. **Concern Reporting**: Returns structured concerns with severity levels
