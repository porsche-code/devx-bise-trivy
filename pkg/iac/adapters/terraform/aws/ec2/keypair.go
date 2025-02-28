package ec2

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ec2"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func adaptKeyPairs(modules terraform.Modules) []ec2.KeyPair {
	var keyPairs []ec2.KeyPair
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_key_pair") {
			keyPairs = append(keyPairs, adaptKeyPair(resource))
		}
	}
	return keyPairs
}

func adaptKeyPair(resource *terraform.Block) ec2.KeyPair {
	keyPair := ec2.KeyPair{
		Metadata:      resource.GetMetadata(),
		KeyName:       resource.GetAttribute("key_name").AsStringValueOrDefault("", resource),
		KeyNamePrefix: resource.GetAttribute("key_name_prefix").AsStringValueOrDefault("", resource),
		PublicKey:     resource.GetAttribute("public_key").AsStringValueOrDefault("", resource),
		Tags:          resource.GetAttribute("tags").AsMapValue(),
	}
	return keyPair
}
