package config

import (
	"strings"
)

type (
	// TLSclientVerification verification client on TLS handshake
	TLSclientVerification string

	// TLSclientVerifyStrategy - client conn verification strategy
	TLSclientVerifyStrategy = ValueT[TLSclientVerification]

	// TLSprivKeyFile private PEM encoded file
	TLSprivKeyFile = ValueT[string]

	// TLScertFile cert PEM encoded file
	TLScertFile = ValueT[string]

	// TLScaFiles CA PEM encoded list ["file1.pem", "cert.pem",...]
	TLScaFiles = ValueT[[]string]

	// TLSverifysServerName server name to verify on TLS handshake
	TLSverifysServerName = ValueT[string]
)

const (
	// TLSclientSkipVerify - client is nonsecured
	TLSclientSkipVerify TLSclientVerification = "skip"

	// TLSclentCertsRequied - server requires the client must have any cert(s)
	TLSclentCertsRequied TLSclientVerification = "certs-required"

	// TLSclientMustVerify
	TLSclientMustVerify TLSclientVerification = "verify"
)

var _ OneOf[TLSclientVerification] = (*TLSclientVerification)(nil)

// Eq config.OneOf
func (o TLSclientVerification) Eq(other TLSclientVerification) bool {
	return strings.EqualFold(string(o), string(other))
}

// Variants impl config.OneOf
func (TLSclientVerification) Variants() []TLSclientVerification {
	r := [...]TLSclientVerification{
		TLSclientSkipVerify, TLSclentCertsRequied, TLSclientMustVerify,
	}
	return r[:]
}
