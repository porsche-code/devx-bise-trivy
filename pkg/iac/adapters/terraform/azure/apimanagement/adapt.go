package apimanagement

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/apimanagement"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func Adapt(modules terraform.Modules) apimanagement.ApiManagement {
	return apimanagement.ApiManagement{Services: adaptServices(modules)}
}

func adaptServices(modules terraform.Modules) []apimanagement.Service {
	var services []apimanagement.Service

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_api_management") {
			services = append(services, adaptService(resource, module))
		}
	}
	return services
}

func adaptService(resource *terraform.Block, module *terraform.Module) apimanagement.Service {
	var service apimanagement.Service
	var security apimanagement.Security

	service = apimanagement.Service{
		Metadata:          resource.GetMetadata(),
		ResourceGroupName: resource.GetAttribute("resource_group_name").AsStringValueOrDefault("", resource),
		PublisherName:     resource.GetAttribute("publisher_name").AsStringValueOrDefault("", resource),
		PublisherEMail:    resource.GetAttribute("publisher_email").AsStringValueOrDefault("", resource),
		SkuName:           resource.GetAttribute("sku_name").AsStringValueOrDefault("", resource),
		Name:              resource.GetAttribute("name").AsStringValueOrDefault("", resource),
		Location:          resource.GetAttribute("location").AsStringValueOrDefault("", resource),
	}

	if resource.HasChild("security") {
		securityBlock := resource.GetBlock("security")
		security = apimanagement.Security{
			Metadata:            securityBlock.GetMetadata(),
			EnableBackendSsl30:  securityBlock.GetAttribute("enable_backend_ssl30").AsBoolValueOrDefault(false, securityBlock),
			EnableBackendTls10:  securityBlock.GetAttribute("enable_backend_tls10").AsBoolValueOrDefault(false, securityBlock),
			EnableBackendTls11:  securityBlock.GetAttribute("enable_backend_tls11").AsBoolValueOrDefault(false, securityBlock),
			EnableFrontendSsl30: securityBlock.GetAttribute("enable_frontend_ssl30").AsBoolValueOrDefault(false, securityBlock),
			EnableFrontendTls10: securityBlock.GetAttribute("enable_frontend_tls10").AsBoolValueOrDefault(false, securityBlock),
			EnableFrontendTls11: securityBlock.GetAttribute("enable_frontend_tls11").AsBoolValueOrDefault(false, securityBlock),
			TlsEcdheEcdsaWithAes128CbcShaCiphersEnabled: securityBlock.GetAttribute("tls_ecdhe_ecdsa_with_aes128_cbc_sha_ciphers_enabled").AsBoolValueOrDefault(false, securityBlock),
			TlsEcdheEcdsaWithAes256CbcShaCiphersEnabled: securityBlock.GetAttribute("tls_ecdhe_ecdsa_with_aes256_cbc_sha_ciphers_enabled").AsBoolValueOrDefault(false, securityBlock),
			TlsEcdheRsaWithAes128CbcShaCiphersEnabled:   securityBlock.GetAttribute("tls_ecdhe_rsa_with_aes128_cbc_sha_ciphers_enabled").AsBoolValueOrDefault(false, securityBlock),
			TlsEcdheRsaWithAes256CbcShaCiphersEnabled:   securityBlock.GetAttribute("tls_ecdhe_rsa_with_aes256_cbc_sha_ciphers_enabled").AsBoolValueOrDefault(false, securityBlock),
			TlsRsaWithAes128CbcSha256CiphersEnabled:     securityBlock.GetAttribute("tls_rsa_with_aes128_cbc_sha256_ciphers_enabled").AsBoolValueOrDefault(false, securityBlock),
			TlsRsaWithAes128CbcShaCiphersEnabled:        securityBlock.GetAttribute("tls_rsa_with_aes128_cbc_sha_ciphers_enabled").AsBoolValueOrDefault(false, securityBlock),
			TlsRsaWithAes128GcmSha256CiphersEnabled:     securityBlock.GetAttribute("tls_rsa_with_aes128_gcm_sha256_ciphers_enabled").AsBoolValueOrDefault(false, securityBlock),
			TlsRsaWithAes256GcmSha384CiphersEnabled:     securityBlock.GetAttribute("tls_rsa_with_aes256_gcm_sha384_ciphers_enabled").AsBoolValueOrDefault(false, securityBlock),
			TlsRsaWithAes256CbcSha256CiphersEnabled:     securityBlock.GetAttribute("tls_rsa_with_aes256_cbc_sha256_ciphers_enabled").AsBoolValueOrDefault(false, securityBlock),
			TlsRsaWithAes256CbcShaCiphersEnabled:        securityBlock.GetAttribute("tls_rsa_with_aes256_cbc_sha_ciphers_enabled").AsBoolValueOrDefault(false, securityBlock),
			TripleDesCiphersEnabled:                     securityBlock.GetAttribute("triple_des_ciphers_enabled").AsBoolValueOrDefault(false, securityBlock),
		}
		service.Security = security
	}

	return service
}
