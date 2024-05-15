package config

import (
	"strings"
)

// AuthnType is a authentication type variants
type AuthnType string

// AuthnTypeSelector is a authentication type selector
type AuthnTypeSelector = ValueT[AuthnType]

const (
	// AuthnTypeNONE - nonsecured - is by default
	AuthnTypeNONE AuthnType = "none"
	// AuthnTypeTLS - use TLS
	AuthnTypeTLS AuthnType = "tls"
)

var _ OneOf[AuthnType] = (*AuthnType)(nil)

// Eq config.OneOf
func (o AuthnType) Eq(other AuthnType) bool {
	return strings.EqualFold(string(o), string(other))
}

// Variants impl config.OneOf
func (AuthnType) Variants() []AuthnType {
	r := [...]AuthnType{
		AuthnTypeNONE, AuthnTypeTLS,
	}
	return r[:]
}
