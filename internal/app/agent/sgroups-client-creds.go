package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"

	config "github.com/H-BF/corlib/pkg/plain-config"

	"github.com/pkg/errors"
	"go.uber.org/multierr"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

func makeSgroupsClientCreds(ctx context.Context) (creds credentials.TransportCredentials, err error) { //nolint:gocyclo
	defer func() {
		err = errors.WithMessage(err, "make SGroups client creds")
	}()
	var authnType config.AuthnType
	if authnType, err = SGroupsAuthnType.Value(ctx); err != nil {
		return nil, err
	}
	switch authnType {
	case config.AuthnTypeNONE:
		creds = insecure.NewCredentials()
	case config.AuthnTypeTLS:
		keyFilename, e1 := SGroupsTLSprivKeyFile.Value(ctx)
		certFilename, e2 := SGroupsTLScertFile.Value(ctx)
		var skipCerts bool
		if errors.Is(e1, config.ErrNotFound) && errors.Is(e2, config.ErrNotFound) {
			skipCerts = true
		} else if err = multierr.Combine(e1, e2); err != nil {
			return nil, err
		}
		tlsConf := new(tls.Config)
		if !skipCerts {
			var cert tls.Certificate
			if cert, err = tls.LoadX509KeyPair(certFilename, keyFilename); err != nil {
				return nil, errors.WithMessagef(err, "on construct client key('%s')/cert('%s') pair",
					keyFilename, certFilename,
				)
			}
			tlsConf.Certificates = append(tlsConf.Certificates, cert)
		}
		var verifyServer bool
		if verifyServer, err = SGroupsTLSserverVerify.Value(ctx); err != nil {
			return nil, err
		}
		tlsConf.InsecureSkipVerify = !verifyServer
		if verifyServer {
			if tlsConf.ServerName, err = SGroupsTLSserverName.Value(ctx); err != nil && !errors.Is(err, config.ErrNotFound) {
				return nil, err
			}
			var files []string
			if files, err = SGroupsTLSserverCAs.Value(ctx); err != nil {
				return nil, err
			}
			if len(files) == 0 {
				return nil, errors.New("no any server CA is provided")
			}
			caPool := x509.NewCertPool()
			for _, ca := range files {
				var pem []byte
				if pem, err = os.ReadFile(ca); err != nil {
					return nil, errors.WithMessagef(err, "on reading server CA '%s'", ca)
				}
				if !caPool.AppendCertsFromPEM(pem) {
					return nil, errors.Errorf("unable adopt '%s' server CA", ca)
				}
			}
			tlsConf.RootCAs = caPool
		}
		creds = credentials.NewTLS(tlsConf)
	default:
		err = errors.Errorf("unsupported authn type '%s'", authnType)
	}
	return creds, nil
}
