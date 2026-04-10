package s3

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sgl-project/ome/pkg/storage"
)

func TestParseS3URI(t *testing.T) {
	tests := []struct {
		name      string
		uri       string
		wantBucket string
		wantKey    string
		wantErr   bool
	}{
		{
			name:       "simple bucket/key",
			uri:        "s3://my-bucket/models/llama3/weights.safetensors",
			wantBucket: "my-bucket",
			wantKey:    "models/llama3/weights.safetensors",
		},
		{
			name:       "prefix only",
			uri:        "s3://my-bucket/models/llama3/",
			wantBucket: "my-bucket",
			wantKey:    "models/llama3/",
		},
		{
			name:       "bucket only",
			uri:        "s3://my-bucket",
			wantBucket: "my-bucket",
			wantKey:    "",
		},
		{
			name:    "empty string",
			uri:     "",
			wantErr: true,
		},
		{
			name:    "non-s3 uri",
			uri:     "hf://meta-llama/llama3",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bucket, key, err := parseS3URI(tt.uri)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseS3URI(%q) error = %v, wantErr %v", tt.uri, err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if bucket != tt.wantBucket {
					t.Errorf("parseS3URI(%q) bucket = %q, want %q", tt.uri, bucket, tt.wantBucket)
				}
				if key != tt.wantKey {
					t.Errorf("parseS3URI(%q) key = %q, want %q", tt.uri, key, tt.wantKey)
				}
			}
		})
	}
}

func TestIsValidBucketName(t *testing.T) {
	tests := []struct {
		name  string
		bucket string
		valid bool
	}{
		{"valid lowercase", "my-bucket", true},
		{"valid with dots", "my.bucket.name", true},
		{"valid numeric", "123bucket", true},
		{"too short", "ab", false},
		{"starts with hyphen", "-bucket", false},
		{"ends with hyphen", "bucket-", false},
		{"consecutive dots", "bucket..name", false},
		{"consecutive hyphens", "bucket--name", false},
		{"uppercase letters", "MyBucket", false},
		{"IP address format", "192.168.1.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidBucketName(tt.bucket)
			if got != tt.valid {
				t.Errorf("isValidBucketName(%q) = %v, want %v", tt.bucket, got, tt.valid)
			}
		})
	}
}

func TestContentTypeFromKey(t *testing.T) {
	tests := []struct {
		key      string
		expected string
	}{
		{"model.safetensors", "application/octet-stream"},
		{"config.json", "application/json"},
		{"README.md", "text/markdown; charset=utf-8"},
		{"image.png", "image/png"},
		{"noext", "application/octet-stream"},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got := getContentTypeFromKey(tt.key)
			if got != tt.expected {
				t.Errorf("getContentTypeFromKey(%q) = %q, want %q", tt.key, got, tt.expected)
			}
		})
	}
}

func TestIsMultipartETag(t *testing.T) {
	tests := []struct {
		etag     string
		expected bool
	}{
		{"d41d8cd98f00b204e9800998ecf8427e", false},
		{"d41d8cd98f00b204e9800998ecf8427e-3", true},
		{"\"d41d8cd98f00b204e9800998ecf8427e\"", false},
		{"abc-notanumber", true}, // isMultipartETag only checks for dash-split, not numeric part count
	}

	for _, tt := range tests {
		t.Run(tt.etag, func(t *testing.T) {
			got := isMultipartETag(tt.etag)
			if got != tt.expected {
				t.Errorf("isMultipartETag(%q) = %v, want %v", tt.etag, got, tt.expected)
			}
		})
	}
}

func TestValidateETag(t *testing.T) {
	// Create a temp file with known content
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.bin")
	content := []byte("hello world")
	if err := os.WriteFile(testFile, content, 0644); err != nil {
		t.Fatal(err)
	}

	// MD5 of "hello world" = 5eb63bbbe01eeed093cb22bb8f5acdc3
	correctETag := "5eb63bbbe01eeed093cb22bb8f5acdc3"
	wrongETag := "0000000000000000000000000000dead"

	t.Run("correct ETag", func(t *testing.T) {
		if err := validateETag(testFile, correctETag); err != nil {
			t.Errorf("validateETag() with correct ETag returned error: %v", err)
		}
	})

	t.Run("wrong ETag", func(t *testing.T) {
		if err := validateETag(testFile, wrongETag); err == nil {
			t.Error("validateETag() with wrong ETag should return error")
		}
	})

	t.Run("multipart ETag skipped", func(t *testing.T) {
		if err := validateETag(testFile, correctETag+"-3"); err != nil {
			t.Errorf("validateETag() with multipart ETag should skip validation: %v", err)
		}
	})

	t.Run("quoted ETag", func(t *testing.T) {
		if err := validateETag(testFile, fmt.Sprintf("\"%s\"", correctETag)); err != nil {
			t.Errorf("validateETag() with quoted ETag returned error: %v", err)
		}
	})
}

func TestNewS3Provider_CABundle(t *testing.T) {
	// Generate a self-signed CA cert
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"Test CA"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})

	// Create a TLS server using the CA cert
	serverCert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caKey)}),
	)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}}
	server.StartTLS()
	defer server.Close()

	t.Run("with valid CA bundle", func(t *testing.T) {
		config := storage.Config{
			Provider: storage.ProviderS3,
			Bucket:   "test-bucket",
			Region:   "us-east-1",
			Endpoint: server.URL,
			Extra: map[string]interface{}{
				"ca_bundle": string(caCertPEM),
			},
			AuthConfig: &storage.AuthConfig{
				Provider: "aws",
				Type:     "access_key",
				Extra: map[string]interface{}{
					"access_key": map[string]interface{}{
						"access_key_id":     "AKIATEST",
						"secret_access_key": "testsecret",
					},
				},
			},
		}

		// initializeS3Client should succeed with the CA bundle
		_, err := initializeS3Client(context.Background(), config, nil)
		if err != nil {
			t.Errorf("initializeS3Client with valid CA bundle failed: %v", err)
		}
	})

	t.Run("with invalid CA bundle PEM", func(t *testing.T) {
		config := storage.Config{
			Provider: storage.ProviderS3,
			Bucket:   "test-bucket",
			Region:   "us-east-1",
			Endpoint: server.URL,
			Extra: map[string]interface{}{
				"ca_bundle": "not-valid-pem",
			},
		}

		_, err := initializeS3Client(context.Background(), config, nil)
		if err == nil {
			t.Error("initializeS3Client with invalid CA bundle should fail")
		}
	})
}

func TestNormalizeKey(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/prefix/key", "prefix/key"},
		{"prefix/key", "prefix/key"},
		{"///deep/prefix", "//deep/prefix"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeKey(tt.input)
			if got != tt.expected {
				t.Errorf("normalizeKey(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}
