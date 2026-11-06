package certs

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"
)

func TestSelfSigned(t *testing.T) {
	now := time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)
	c, k, err := SelfSigned([]string{"v.witch", "127.0.0.1", "v.witch", ""}, now)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(c, k)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if !IsSelfSigned(cert) || len(cert.DNSNames) != 1 || len(cert.IPAddresses) != 1 {
		t.Fatalf("names %v %v", cert.DNSNames, cert.IPAddresses)
	}
	if err := cert.VerifyHostname("v.witch"); err != nil {
		t.Fatal(err)
	}
	// Apple counts from NotBefore, not from now
	if got := cert.NotAfter.Sub(cert.NotBefore); got > Validity || got > 398*24*time.Hour || TooLong(cert) {
		t.Fatalf("validity %v", got)
	}
	if fp := Fingerprint(cert); len(fp) != 95 {
		t.Fatalf("fingerprint %q", fp)
	}
}
