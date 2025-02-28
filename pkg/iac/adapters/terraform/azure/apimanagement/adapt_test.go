package apimanagement

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/apimanagement"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  apimanagement.ApiManagement
	}{
		{
			name: "minimal",
			terraform: `
			resource "azurerm_api_management" "example_min" {
  				name                = "example-apim"
  				location            = "West Europe"
  				resource_group_name = "example-resources"
  				publisher_name      = "My Company"
  				publisher_email     = "company@terraform.io"

  				sku_name = "Developer_1"
			}
`,
			expected: apimanagement.ApiManagement{
				Services: []apimanagement.Service{
					{
						Metadata:          iacTypes.NewTestMetadata(),
						ResourceGroupName: iacTypes.StringTest("example-resources"),
						PublisherName:     iacTypes.StringTest("My Company"),
						PublisherEMail:    iacTypes.StringTest("company@terraform.io"),
						SkuName:           iacTypes.StringTest("Developer_1"),
						Name:              iacTypes.StringTest("example-apim"),
						Location:          iacTypes.StringTest("West Europe"),
					},
				},
			},
		},
		{
			name: "with-security-all-ciphers",
			terraform: `
			resource "azurerm_api_management" "example_min" {
  				name                = "example-apim"
  				location            = "West Europe"
  				resource_group_name = "example-resources"
  				publisher_name      = "My Company"
  				publisher_email     = "company@terraform.io"

  				sku_name = "Developer_1"

				security {
					enable_backend_ssl30  = true
					enable_backend_tls10  = true
					enable_backend_tls11  = true
					enable_frontend_ssl30 = true
					enable_frontend_tls10 = true
					enable_frontend_tls11 = true
				
					tls_ecdhe_ecdsa_with_aes128_cbc_sha_ciphers_enabled = true
					tls_ecdhe_ecdsa_with_aes256_cbc_sha_ciphers_enabled = true
					tls_ecdhe_rsa_with_aes128_cbc_sha_ciphers_enabled = true
					tls_ecdhe_rsa_with_aes256_cbc_sha_ciphers_enabled = true
					tls_rsa_with_aes128_cbc_sha256_ciphers_enabled = true
					tls_rsa_with_aes128_cbc_sha_ciphers_enabled = true
					tls_rsa_with_aes128_gcm_sha256_ciphers_enabled = true
					tls_rsa_with_aes256_gcm_sha384_ciphers_enabled = true
					tls_rsa_with_aes256_cbc_sha256_ciphers_enabled = true
					tls_rsa_with_aes256_cbc_sha_ciphers_enabled = true
					triple_des_ciphers_enabled = true
				}
			}
`,
			expected: apimanagement.ApiManagement{
				Services: []apimanagement.Service{
					{
						Metadata:          iacTypes.NewTestMetadata(),
						ResourceGroupName: iacTypes.StringTest("example-resources"),
						PublisherName:     iacTypes.StringTest("My Company"),
						PublisherEMail:    iacTypes.StringTest("company@terraform.io"),
						SkuName:           iacTypes.StringTest("Developer_1"),
						Name:              iacTypes.StringTest("example-apim"),
						Location:          iacTypes.StringTest("West Europe"),
						Security: apimanagement.Security{
							Metadata:            iacTypes.NewTestMetadata(),
							EnableBackendSsl30:  iacTypes.BoolTest(true),
							EnableBackendTls10:  iacTypes.BoolTest(true),
							EnableBackendTls11:  iacTypes.BoolTest(true),
							EnableFrontendSsl30: iacTypes.BoolTest(true),
							EnableFrontendTls10: iacTypes.BoolTest(true),
							EnableFrontendTls11: iacTypes.BoolTest(true),
							TlsEcdheEcdsaWithAes128CbcShaCiphersEnabled: iacTypes.BoolTest(true),
							TlsEcdheEcdsaWithAes256CbcShaCiphersEnabled: iacTypes.BoolTest(true),
							TlsEcdheRsaWithAes128CbcShaCiphersEnabled:   iacTypes.BoolTest(true),
							TlsEcdheRsaWithAes256CbcShaCiphersEnabled:   iacTypes.BoolTest(true),
							TlsRsaWithAes128CbcSha256CiphersEnabled:     iacTypes.BoolTest(true),
							TlsRsaWithAes128CbcShaCiphersEnabled:        iacTypes.BoolTest(true),
							TlsRsaWithAes128GcmSha256CiphersEnabled:     iacTypes.BoolTest(true),
							TlsRsaWithAes256GcmSha384CiphersEnabled:     iacTypes.BoolTest(true),
							TlsRsaWithAes256CbcSha256CiphersEnabled:     iacTypes.BoolTest(true),
							TlsRsaWithAes256CbcShaCiphersEnabled:        iacTypes.BoolTest(true),
							TripleDesCiphersEnabled:                     iacTypes.BoolTest(true),
						},
					},
				},
			},
		},
		{
			name: "with-security-one-cipher",
			terraform: `
			resource "azurerm_api_management" "example_min" {
  				name                = "example-apim"
  				location            = "West Europe"
  				resource_group_name = "example-resources"
  				publisher_name      = "My Company"
  				publisher_email     = "company@terraform.io"

  				sku_name = "Developer_1"

				security {
					tls_ecdhe_ecdsa_with_aes128_cbc_sha_ciphers_enabled = true
				}
			}
`,
			expected: apimanagement.ApiManagement{
				Services: []apimanagement.Service{
					{
						Metadata:          iacTypes.NewTestMetadata(),
						ResourceGroupName: iacTypes.StringTest("example-resources"),
						PublisherName:     iacTypes.StringTest("My Company"),
						PublisherEMail:    iacTypes.StringTest("company@terraform.io"),
						SkuName:           iacTypes.StringTest("Developer_1"),
						Name:              iacTypes.StringTest("example-apim"),
						Location:          iacTypes.StringTest("West Europe"),
						Security: apimanagement.Security{
							Metadata: iacTypes.NewTestMetadata(),
							TlsEcdheEcdsaWithAes128CbcShaCiphersEnabled: iacTypes.BoolTest(true),
							TlsEcdheEcdsaWithAes256CbcShaCiphersEnabled: iacTypes.BoolTest(false),
							TlsEcdheRsaWithAes128CbcShaCiphersEnabled:   iacTypes.BoolTest(false),
							TlsEcdheRsaWithAes256CbcShaCiphersEnabled:   iacTypes.BoolTest(false),
							TlsRsaWithAes128CbcSha256CiphersEnabled:     iacTypes.BoolTest(false),
							TlsRsaWithAes128CbcShaCiphersEnabled:        iacTypes.BoolTest(false),
							TlsRsaWithAes128GcmSha256CiphersEnabled:     iacTypes.BoolTest(false),
							TlsRsaWithAes256GcmSha384CiphersEnabled:     iacTypes.BoolTest(false),
							TlsRsaWithAes256CbcSha256CiphersEnabled:     iacTypes.BoolTest(false),
							TlsRsaWithAes256CbcShaCiphersEnabled:        iacTypes.BoolTest(false),
							TripleDesCiphersEnabled:                     iacTypes.BoolTest(false),
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := Adapt(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
			resource "azurerm_api_management" "example_min" {
  				name                = "example-apim"
  				location            = "West Europe"
  				resource_group_name = "example-resources"
  				publisher_name      = "My Company"
  				publisher_email     = "company@terraform.io"

  				sku_name = "Developer_1"

				security {
					enable_backend_ssl30  = true
					enable_backend_tls10  = true
					enable_backend_tls11  = true
					enable_frontend_ssl30 = true
					enable_frontend_tls10 = true
					enable_frontend_tls11 = true
				
					tls_ecdhe_ecdsa_with_aes128_cbc_sha_ciphers_enabled = true
					tls_ecdhe_ecdsa_with_aes256_cbc_sha_ciphers_enabled = true
					tls_ecdhe_rsa_with_aes128_cbc_sha_ciphers_enabled = true
					tls_ecdhe_rsa_with_aes256_cbc_sha_ciphers_enabled = true
					tls_rsa_with_aes128_cbc_sha256_ciphers_enabled = true
					tls_rsa_with_aes128_cbc_sha_ciphers_enabled = true
					tls_rsa_with_aes128_gcm_sha256_ciphers_enabled = true
					tls_rsa_with_aes256_gcm_sha384_ciphers_enabled = true
					tls_rsa_with_aes256_cbc_sha256_ciphers_enabled = true
					tls_rsa_with_aes256_cbc_sha_ciphers_enabled = true
					triple_des_ciphers_enabled = true
				}
			}
`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Services, 1)
	service := adapted.Services[0]

	assert.Equal(t, 2, service.Metadata.Range().GetStartLine())
	assert.Equal(t, 31, service.Metadata.Range().GetEndLine())

	assert.Equal(t, 3, service.Name.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, service.Name.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, service.Location.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, service.Location.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 5, service.ResourceGroupName.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 5, service.ResourceGroupName.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 6, service.PublisherName.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 6, service.PublisherName.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 7, service.PublisherEMail.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, service.PublisherEMail.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 9, service.SkuName.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 9, service.SkuName.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 12, service.Security.EnableBackendSsl30.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 12, service.Security.EnableBackendSsl30.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 13, service.Security.EnableBackendTls10.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 13, service.Security.EnableBackendTls10.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 14, service.Security.EnableBackendTls11.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 14, service.Security.EnableBackendTls11.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 15, service.Security.EnableFrontendSsl30.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 15, service.Security.EnableFrontendSsl30.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 16, service.Security.EnableFrontendTls10.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 16, service.Security.EnableFrontendTls10.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 17, service.Security.EnableFrontendTls11.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 17, service.Security.EnableFrontendTls11.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 19, service.Security.TlsEcdheEcdsaWithAes128CbcShaCiphersEnabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 19, service.Security.TlsEcdheEcdsaWithAes128CbcShaCiphersEnabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 20, service.Security.TlsEcdheEcdsaWithAes256CbcShaCiphersEnabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 20, service.Security.TlsEcdheEcdsaWithAes256CbcShaCiphersEnabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 23, service.Security.TlsRsaWithAes128CbcSha256CiphersEnabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 23, service.Security.TlsRsaWithAes128CbcSha256CiphersEnabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 24, service.Security.TlsRsaWithAes128CbcShaCiphersEnabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 24, service.Security.TlsRsaWithAes128CbcShaCiphersEnabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 25, service.Security.TlsRsaWithAes128GcmSha256CiphersEnabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 25, service.Security.TlsRsaWithAes128GcmSha256CiphersEnabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 26, service.Security.TlsRsaWithAes256GcmSha384CiphersEnabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 26, service.Security.TlsRsaWithAes256GcmSha384CiphersEnabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 27, service.Security.TlsRsaWithAes256CbcSha256CiphersEnabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 27, service.Security.TlsRsaWithAes256CbcSha256CiphersEnabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 28, service.Security.TlsRsaWithAes256CbcShaCiphersEnabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 28, service.Security.TlsRsaWithAes256CbcShaCiphersEnabled.GetMetadata().Range().GetEndLine())
}
