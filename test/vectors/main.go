// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Command vectors generates the shared cross-consistency test vectors for
// openaic using github.com/varwof/types (pure stdlib, the normative AIC type
// definitions used by both the Go and C implementations):
//
//   out/user-principal.pem      principal cert (SPKI matches keyHash)
//   out/aic-good.pem            agent cert (self-signed) with valid AIC
//   out/aic-tampered.pem        same cert, DA signature corrupted
//   out/aic-spki-mismatch.pem   cert with keyHash mismatch vs user SPKI
//   out/aic.der                 raw AIC extension DER (the SEQUENCE value)
//
// The C side (test/aic_ext_test.c against the patched OpenSSL) must parse the
// same DER and reconstruct identical field values; the reverse direction is
// exercised by OpenSSL-emitted DER parsed back through types.ParseAIC.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	pki "github.com/varwof/types"
)

func writePEM(path string, typ string, der []byte) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600)
}

func selfSigned(key *ecdsa.PrivateKey, cn, realm string, extra []pkix.Extension) (*x509.Certificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(time.Now().UnixNano() % 1e9),
		Subject:         pkix.Name{CommonName: cn, Organization: []string{realm}},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: extra,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// delegationTBS mirrors the exact TBS the CA verifies (types.DelegationAuthTBS
// field order + tags), so signatures produced here verify on both sides.
func delegationTBS(cfg pki.AIC, da *pki.DelegationAuthorization) ([]byte, error) {
	pu := cfg.PrincipalUid
	tbs := pki.DelegationAuthTBS{
		Version:  1,
		AgentId:  cfg.AgentId,
		PrincipalUid: pki.PrincipalUid{
			Version:    pu.Version,
			Realm:      pu.Realm,
			Identifier: pu.Identifier,
			KeyHash:    pu.KeyHash,
			HashAlgo:   pki.AlgorithmIdentifier{Algorithm: pu.HashAlgo.Algorithm},
		},
		Reason:                   pki.Reason{ReasonCode: da.Reason.ReasonCode, Description: da.Reason.Description},
		Capabilities:             cfg.Capabilities,
		DelegationMode:           pki.DelegationMode(cfg.DelegationMode),
		AuthorizationConstraints: cfg.AuthorizationConstraints,
		RequestedLifetime:        da.RequestedLifetime,
		Timestamp:                da.Timestamp,
		Nonce:                    da.Nonce,
	}
	return asn1.Marshal(tbs)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func main() {
	outDir := flag.String("out", "out/", "output directory for vectors")
	flag.Parse()
	if err := os.MkdirAll(*outDir, 0o700); err != nil {
		fatal(err)
	}

	userKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fatal(err)
	}
	userCert, err := selfSigned(userKey, "alice", "acme", nil)
	if err != nil {
		fatal(err)
	}
	if err := writePEM(filepath.Join(*outDir, "user-principal.pem"), "CERTIFICATE", userCert.Raw); err != nil {
		fatal(err)
	}

	pu := pki.MakePrincipalUidFromCert("acme", "alice", userCert)

	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fatal(err)
	}

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		fatal(err)
	}
	now := time.Now().UTC().Round(time.Second)

	mkAIC := func() (pki.AIC, *pki.DelegationAuthorization) {
		da := &pki.DelegationAuthorization{
			Reason:             pki.Reason{ReasonCode: "maintenance", Description: "scheduled maintenance window"},
			RequestedLifetime:  3600,
			Timestamp:          now,
			Nonce:              nonce,
			SignatureAlgorithm: pki.AlgorithmIdentifier{Algorithm: pki.OIDSigECDSAWithSHA256},
		}
		cfg := pki.AIC{
			Version:        1,
			AgentId:        "agent-7",
			PrincipalUid:   pu,
			DelegationMode: pki.DelegationMode(0), /* authorized */
			Capabilities: []pki.Capability{
				{SchemeId: "tt", CapabilityId: "smart-device", Parameters: []byte(`{"level":2}`)},
			},
			AuthorizationConstraints: []pki.Capability{
				{SchemeId: "constraint", CapabilityId: "max-concurrent", Parameters: []byte(`{"max":3}`)},
			},
			DelegationAuthorization: *da,
		}
		return cfg, da
	}

	buildCertWithAIC := func(cfg pki.AIC, da *pki.DelegationAuthorization, corruptSig bool) (*x509.Certificate, []byte) {
		tbs, err := delegationTBS(cfg, da)
		if err != nil {
			fatal(err)
		}
		digest := sha256.Sum256(tbs)
		sig, err := ecdsa.SignASN1(rand.Reader, userKey, digest[:])
		if err != nil {
			fatal(err)
		}
		if corruptSig {
			sig[len(sig)-1] ^= 0x01
		}
		da.SignatureValue = sig
		cfg.DelegationAuthorization.SignatureValue = sig

		// Validate before emitting (spec constraints).
		if err := pki.ValidateAIC(&cfg); err != nil {
			fatal(fmt.Errorf("validate AIC: %w", err))
		}
		aicDER, err := asn1.Marshal(cfg)
		if err != nil {
			fatal(err)
		}
		cert, err := selfSigned(agentKey, "agent-7", "acme",
			[]pkix.Extension{{Id: pki.OIDAIC, Critical: false, Value: aicDER}})
		if err != nil {
			fatal(err)
		}
		return cert, aicDER
	}

	cfgGood, daGood := mkAIC()
	certGood, aicDER := buildCertWithAIC(cfgGood, daGood, false)
	if err := writePEM(filepath.Join(*outDir, "aic-good.pem"), "CERTIFICATE", certGood.Raw); err != nil {
		fatal(err)
	}
	if err := os.WriteFile(filepath.Join(*outDir, "aic.der"), aicDER, 0o600); err != nil {
		fatal(err)
	}

	cfgT, daT := mkAIC()
	certT, _ := buildCertWithAIC(cfgT, daT, true)
	if err := writePEM(filepath.Join(*outDir, "aic-tampered.pem"), "CERTIFICATE", certT.Raw); err != nil {
		fatal(err)
	}

	mismatchKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fatal(err)
	}
	mismatchCert, err := selfSigned(mismatchKey, "mallory", "acme", nil)
	if err != nil {
		fatal(err)
	}
	cfgBad, daBad := mkAIC()
	cfgBad.PrincipalUid = pki.MakePrincipalUidFromCert("acme", "mallory", mismatchCert)
	certBad, _ := buildCertWithAIC(cfgBad, daBad, false)
	if err := writePEM(filepath.Join(*outDir, "aic-spki-mismatch.pem"), "CERTIFICATE", certBad.Raw); err != nil {
		fatal(err)
	}

	fmt.Printf("vectors written to %s (good/tampered/spki-mismatch/user)\n", *outDir)
}
