package ec2

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type KeyPair struct {
	Metadata      iacTypes.Metadata
	KeyName       iacTypes.StringValue
	KeyNamePrefix iacTypes.StringValue
	PublicKey     iacTypes.StringValue
	Tags          iacTypes.MapValue
}
