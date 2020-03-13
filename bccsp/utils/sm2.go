package utils

import "github.com/tjfoc/gmsm/sm2"

func DERToSM2Certificate(asn1Data []byte) (*sm2.Certificate, error) {
	return sm2.ParseCertificate(asn1Data)
}

