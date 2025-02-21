package apimanagement

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type ApiManagement struct {
	Services []Service
}

type Service struct {
	Metadata          iacTypes.Metadata
	ResourceGroupName iacTypes.StringValue
	PublisherName     iacTypes.StringValue
	PublisherEMail    iacTypes.StringValue
	SkuName           iacTypes.StringValue
	Name              iacTypes.StringValue
	Location          iacTypes.StringValue
	Security          Security
}

type Security struct {
	Metadata                                    iacTypes.Metadata
	EnableBackendSsl30                          iacTypes.BoolValue
	EnableBackendTls10                          iacTypes.BoolValue
	EnableBackendTls11                          iacTypes.BoolValue
	EnableFrontendSsl30                         iacTypes.BoolValue
	EnableFrontendTls10                         iacTypes.BoolValue
	EnableFrontendTls11                         iacTypes.BoolValue
	TlsEcdheEcdsaWithAes128CbcShaCiphersEnabled iacTypes.BoolValue
	TlsEcdheEcdsaWithAes256CbcShaCiphersEnabled iacTypes.BoolValue
	TlsEcdheRsaWithAes128CbcShaCiphersEnabled   iacTypes.BoolValue
	TlsEcdheRsaWithAes256CbcShaCiphersEnabled   iacTypes.BoolValue
	TlsRsaWithAes128CbcSha256CiphersEnabled     iacTypes.BoolValue
	TlsRsaWithAes128CbcShaCiphersEnabled        iacTypes.BoolValue
	TlsRsaWithAes128GcmSha256CiphersEnabled     iacTypes.BoolValue
	TlsRsaWithAes256GcmSha384CiphersEnabled     iacTypes.BoolValue
	TlsRsaWithAes256CbcSha256CiphersEnabled     iacTypes.BoolValue
	TlsRsaWithAes256CbcShaCiphersEnabled        iacTypes.BoolValue
	TripleDesCiphersEnabled                     iacTypes.BoolValue
}
