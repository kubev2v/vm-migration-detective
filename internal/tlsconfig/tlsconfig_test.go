package tlsconfig

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kubev2v/vm-migration-detective/pkg/types"
)

// generateTestCert creates a self-signed certificate for testing
func generateTestCert() ([]byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-cert",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return certPEM, nil
}

func TestNormalizeThumbprint(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    string
		expectError bool
	}{
		{
			name:     "uppercase colon-separated",
			input:    "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD",
			expected: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD",
		},
		{
			name:     "lowercase colon-separated",
			input:    "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd",
			expected: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD",
		},
		{
			name:     "no separators",
			input:    "aabbccddeeff00112233445566778899aabbccdd",
			expected: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD",
		},
		{
			name:     "space-separated",
			input:    "AA BB CC DD EE FF 00 11 22 33 44 55 66 77 88 99 AA BB CC DD",
			expected: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD",
		},
		{
			name:        "too short",
			input:       "AA:BB:CC:DD",
			expectError: true,
		},
		{
			name:        "too long",
			input:       "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA",
			expectError: true,
		},
		{
			name:        "invalid hex",
			input:       "GG:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := NormalizeThumbprint(tt.input)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if result != tt.expected {
					t.Errorf("Expected %s, got %s", tt.expected, result)
				}
			}
		})
	}
}

func TestComputeThumbprint(t *testing.T) {
	// Test with known certificate data
	certDER := []byte("test certificate data")
	thumbprint := ComputeThumbprint(certDER)
	expected := "9A:FE:3E:76:58:5E:8C:F6:1A:F6:29:3A:70:3B:49:28:2A:88:77:A7"
	if thumbprint != expected {
		t.Errorf("Expected SHA-1 thumbprint %s, got %s", expected, thumbprint)
	}

	// Should be 40 hex chars with colons (SHA-1)
	if len(thumbprint) != 59 { // 40 hex chars + 19 colons = 59
		t.Errorf("Expected thumbprint length 95, got %d", len(thumbprint))
	}

	// Should be uppercase
	for _, c := range thumbprint {
		if c >= 'a' && c <= 'z' {
			t.Errorf("Thumbprint contains lowercase characters: %s", thumbprint)
			break
		}
	}

	// Should have colons every 3rd character (except last)
	for i := 2; i < len(thumbprint); i += 3 {
		if thumbprint[i] != ':' {
			t.Errorf("Expected colon at position %d, got %c", i, thumbprint[i])
		}
	}
}

func TestLoadCACertPool(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := t.TempDir()

	t.Run("valid PEM", func(t *testing.T) {
		// Generate a test certificate
		validPEM, err := generateTestCert()
		if err != nil {
			t.Fatalf("Failed to generate test cert: %v", err)
		}

		certPath := filepath.Join(tmpDir, "valid.pem")
		if err := os.WriteFile(certPath, validPEM, 0600); err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}

		pool, err := LoadCACertPool(certPath)
		if err != nil {
			t.Errorf("Unexpected error loading valid PEM: %v", err)
		}
		if pool == nil {
			t.Error("Expected non-nil cert pool")
		}
	})

	t.Run("invalid PEM", func(t *testing.T) {
		invalidPath := filepath.Join(tmpDir, "invalid.pem")
		if err := os.WriteFile(invalidPath, []byte("not a certificate"), 0600); err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}

		_, err := LoadCACertPool(invalidPath)
		if err == nil {
			t.Error("Expected error for invalid PEM")
		}
	})

	t.Run("missing file", func(t *testing.T) {
		missingPath := filepath.Join(tmpDir, "nonexistent.pem")
		_, err := LoadCACertPool(missingPath)
		if err == nil {
			t.Error("Expected error for missing file")
		}
	})
}

func TestFromCredentials(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := t.TempDir()

	// Create a valid CA cert file
	validPEM, err := generateTestCert()
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	certPath := filepath.Join(tmpDir, "ca.pem")
	if err := os.WriteFile(certPath, validPEM, 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	tests := []struct {
		name             string
		creds            types.Credentials
		expectInsecure   bool
		expectDeprecated bool
		expectError      bool
		expectThumbprint bool
		expectRootCAs    bool
	}{
		{
			name: "explicit insecure",
			creds: types.Credentials{
				VCenterURL:  "https://vcenter.example.com",
				Username:    "admin",
				Password:    "password",
				TLSInsecure: true,
			},
			expectInsecure:   true,
			expectDeprecated: false,
		},
		{
			name: "valid thumbprint",
			creds: types.Credentials{
				VCenterURL:    "https://vcenter.example.com",
				Username:      "admin",
				Password:      "password",
				TLSThumbprint: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD",
			},
			expectInsecure:   false,
			expectDeprecated: false,
			expectThumbprint: true,
		},
		{
			name: "invalid thumbprint",
			creds: types.Credentials{
				VCenterURL:    "https://vcenter.example.com",
				Username:      "admin",
				Password:      "password",
				TLSThumbprint: "invalid",
			},
			expectError: true,
		},
		{
			name: "valid CA cert",
			creds: types.Credentials{
				VCenterURL: "https://vcenter.example.com",
				Username:   "admin",
				Password:   "password",
				TLSCACert:  certPath,
			},
			expectInsecure:   false,
			expectDeprecated: false,
			expectRootCAs:    true,
		},
		{
			name: "invalid CA path",
			creds: types.Credentials{
				VCenterURL: "https://vcenter.example.com",
				Username:   "admin",
				Password:   "password",
				TLSCACert:  "/nonexistent/path/ca.pem",
			},
			expectError: true,
		},
		{
			name: "no TLS config (deprecated default)",
			creds: types.Credentials{
				VCenterURL: "https://vcenter.example.com",
				Username:   "admin",
				Password:   "password",
			},
			expectInsecure:   true,
			expectDeprecated: true,
		},
		{
			name: "both thumbprint and CA (thumbprint takes precedence)",
			creds: types.Credentials{
				VCenterURL:    "https://vcenter.example.com",
				Username:      "admin",
				Password:      "password",
				TLSThumbprint: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD",
				TLSCACert:     certPath,
			},
			expectInsecure:   false,
			expectDeprecated: false,
			expectThumbprint: true,
			expectRootCAs:    false, // Thumbprint takes precedence
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := FromCredentials(tt.creds, nil)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if config.Insecure != tt.expectInsecure {
				t.Errorf("Expected Insecure=%v, got %v", tt.expectInsecure, config.Insecure)
			}

			if config.IsDeprecatedDefault != tt.expectDeprecated {
				t.Errorf("Expected IsDeprecatedDefault=%v, got %v", tt.expectDeprecated, config.IsDeprecatedDefault)
			}

			if tt.expectThumbprint && config.Thumbprint == "" {
				t.Error("Expected thumbprint to be set")
			}

			if tt.expectRootCAs && config.RootCAs == nil {
				t.Error("Expected RootCAs to be set")
			}

			if !tt.expectRootCAs && config.RootCAs != nil {
				t.Error("Expected RootCAs to be nil")
			}
		})
	}
}

func TestConfigHelperMethods(t *testing.T) {
	t.Run("ForGovmomi", func(t *testing.T) {
		insecureConfig := &Config{Insecure: true}
		if !insecureConfig.ForGovmomi() {
			t.Error("Expected ForGovmomi to return true for insecure config")
		}

		secureConfig := &Config{Insecure: false}
		if secureConfig.ForGovmomi() {
			t.Error("Expected ForGovmomi to return false for secure config")
		}
	})

	t.Run("ForNBDKit", func(t *testing.T) {
		insecureConfig := &Config{Insecure: true, Thumbprint: "AA:BB:CC"}
		if insecureConfig.ForNBDKit() != "" {
			t.Error("Expected ForNBDKit to return empty string for insecure config")
		}

		thumbprint := "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
		secureConfig := &Config{Insecure: false, Thumbprint: thumbprint}
		if secureConfig.ForNBDKit() != thumbprint {
			t.Errorf("Expected ForNBDKit to return thumbprint, got %s", secureConfig.ForNBDKit())
		}
	})

	t.Run("ForVirtV2V", func(t *testing.T) {
		insecureConfig := &Config{Insecure: true}
		if insecureConfig.ForVirtV2V("") != "no_verify=1" {
			t.Error("Expected ForVirtV2V to return no_verify=1 for insecure config")
		}

		// CA config with path
		secureConfig := &Config{Insecure: false, RootCAs: &x509.CertPool{}}
		result := secureConfig.ForVirtV2V("/path/to/ca.pem")
		if result != "cacert=/path/to/ca.pem" {
			t.Errorf("Expected cacert parameter, got %s", result)
		}

		// Thumbprint config (no direct support in virt-v2v)
		thumbprintConfig := &Config{Insecure: false, Thumbprint: "AA:BB:CC"}
		result = thumbprintConfig.ForVirtV2V("")
		if result != "no_verify=1" {
			t.Errorf("Expected no_verify=1 for thumbprint config, got %s", result)
		}
	})
}
