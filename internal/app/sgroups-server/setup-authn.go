package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"

	config "github.com/H-BF/corlib/pkg/plain-config"

	"github.com/pkg/errors"
)

type authnType interface {
	isAuthnType()
}

type authnTLS struct {
	authnType
	conf *tls.Config
}

func whenAuthn(ctx context.Context, consume func(authnType) error) error {
	authn, e := AuthnType.Value(ctx)
	if e != nil {
		return e
	}
	switch authn {
	case config.AuthnTypeTLS:
		cnf, err := setupTLS(ctx)
		if err != nil {
			return errors.WithMessage(err, "on setup TLS")
		}
		return consume(authnTLS{conf: cnf})
	case config.AuthnTypeNONE:
	default:
		return errors.Errorf("unsupported authn type '%s'", authn)
	}
	return nil
}

func setupTLS(ctx context.Context) (ret *tls.Config, err error) {
	var (
		keyFilename  string
		certFilename string
		caFiles      []string
	)
	if keyFilename, err = TLSprivKeyFile.Value(ctx); err != nil {
		return ret, err
	}
	if certFilename, err = TLScertFile.Value(ctx); err != nil {
		return ret, err
	}
	caFiles, err = TLSclientCAfiles.Value(ctx)
	if err != nil && !errors.Is(err, config.ErrNotFound) {
		return ret, err
	}
	var cert tls.Certificate
	if cert, err = tls.LoadX509KeyPair(certFilename, keyFilename); err != nil {
		return ret, errors.WithMessagef(err, "on construct server key('%s')/cert('%s') pair",
			keyFilename, certFilename,
		)
	}
	ret = new(tls.Config)
	ret.Certificates = append(ret.Certificates, cert)
	if len(caFiles) > 0 {
		caPool := x509.NewCertPool()
		for i := range caFiles {
			ca := caFiles[i]
			var pem []byte
			if pem, err = os.ReadFile(ca); err != nil {
				return ret, errors.WithMessagef(err, "unable to read '%s' cert file", ca)
			}
			if !caPool.AppendCertsFromPEM(pem) {
				return ret, errors.Errorf("unable add '%s' cert onto ca-pool", ca)
			}
		}
		ret.ClientCAs = caPool
	}

	var verifyClient config.TLSclientVerification
	if verifyClient, err = TLSclientVerifyStrategy.Value(ctx); err != nil {
		return nil, err
	}
	switch verifyClient {
	case config.TLSclientSkipVerify:
		ret.ClientAuth = tls.NoClientCert
	case config.TLSclentCertsRequied:
		ret.ClientAuth = tls.RequireAnyClientCert
	case config.TLSclientMustVerify:
		if ret.ClientCAs == nil {
			return nil, errors.Errorf("should provide CA client cert(s) in config '%s' ",
				TLSclientCAfiles)
		}
		ret.ClientAuth = tls.RequireAndVerifyClientCert
	default:
		return nil, errors.Errorf("unsupported '%s' client-verification", verifyClient)
	}
	return ret, nil
}
