package cmd

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
)

func GenerateThumbprint(host string, noColons bool) string {
	issuer, err := url.Parse(host)
	panicIfError(err)

	certs, err := fetchCertificate(issuer)
	panicIfError(err)

	cert := certs[len(certs)-1]

	fingerprint := sha1.Sum(cert.Raw)

	var buf bytes.Buffer
	for i, f := range fingerprint {
		if !noColons && i > 0 {
			fmt.Fprintf(&buf, ":")
		}
		fmt.Fprintf(&buf, "%02X", f)
	}
	return fmt.Sprintf("%s", buf.String())
}

func panicIfError(err error) {
	if err != nil {
		panic(err)
	}
}

func fetchCertificate(targetURL *url.URL) ([]*x509.Certificate, error) {
	client := &http.Client{}

	resp, err := client.Head(targetURL.String())
	panicIfError(err)
	defer resp.Body.Close()

	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		return resp.TLS.PeerCertificates, nil
	}

	return nil, fmt.Errorf("got back response (status: %s) with no certificates from URL '%s': %w", resp.Status, targetURL.Scheme, err)
}
