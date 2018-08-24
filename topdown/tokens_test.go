package topdown

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"github.com/open-policy-agent/opa/ast"
	"testing"
)

func TestParseTokenConstraints(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		var constraints tokenConstraints
		var err error
		c := ast.NewObject()
		constraints, err = parseTokenConstraints(c)
		if err != nil {
			t.Fatalf("parseTokenConstraints: %v", err)
		}
		if constraints.alg != "" {
			t.Errorf("alg: %v", constraints.alg)
		}
		if constraints.key != nil {
			t.Errorf("key: %v", constraints.key)
		}
	})
	t.Run("Alg", func(t *testing.T) {
		var constraints tokenConstraints
		var err error
		c := ast.NewObject()
		c.Insert(ast.StringTerm("alg"), ast.StringTerm("RS256"))
		constraints, err = parseTokenConstraints(c)
		if err != nil {
			t.Fatalf("parseTokenConstraints: %v", err)
		}
		if constraints.alg != "RS256" {
			t.Errorf("alg: %v", constraints.alg)
		}
	})
	t.Run("Cert", func(t *testing.T) {
		var constraints tokenConstraints
		var err error
		c := ast.NewObject()
		c.Insert(ast.StringTerm("cert"), ast.StringTerm(`-----BEGIN CERTIFICATE-----
MIIBcDCCARagAwIBAgIJAMZmuGSIfvgzMAoGCCqGSM49BAMCMBMxETAPBgNVBAMM
CHdoYXRldmVyMB4XDTE4MDgxMDE0Mjg1NFoXDTE4MDkwOTE0Mjg1NFowEzERMA8G
A1UEAwwId2hhdGV2ZXIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATPwn3WCEXL
mjp/bFniDwuwsfu7bASlPae2PyWhqGeWwe23Xlyx+tSqxlkXYe4pZ23BkAAscpGj
yn5gXHExyDlKo1MwUTAdBgNVHQ4EFgQUElRjSoVgKjUqY5AXz2o74cLzzS8wHwYD
VR0jBBgwFoAUElRjSoVgKjUqY5AXz2o74cLzzS8wDwYDVR0TAQH/BAUwAwEB/zAK
BggqhkjOPQQDAgNIADBFAiEA4yQ/88ZrUX68c6kOe9G11u8NUaUzd8pLOtkKhniN
OHoCIHmNX37JOqTcTzGn2u9+c8NlnvZ0uDvsd1BmKPaUmjmm
-----END CERTIFICATE-----`))
		constraints, err = parseTokenConstraints(c)
		if err != nil {
			t.Fatalf("parseTokenConstraints: %v", err)
		}
		pubKey := constraints.key.(*ecdsa.PublicKey)
		if pubKey.Curve != elliptic.P256() {
			t.Errorf("curve: %v", pubKey.Curve)
		}
		if pubKey.X.Text(16) != "cfc27dd60845cb9a3a7f6c59e20f0bb0b1fbbb6c04a53da7b63f25a1a86796c1" {
			t.Errorf("x: %x", pubKey.X)
		}
		if pubKey.Y.Text(16) != "edb75e5cb1fad4aac6591761ee29676dc190002c7291a3ca7e605c7131c8394a" {
			t.Errorf("y: %x", pubKey.Y)
		}
	})
	t.Run("Unrecognized", func(t *testing.T) {
		var err error
		c := ast.NewObject()
		c.Insert(ast.StringTerm("hatever"), ast.StringTerm("junk"))
		_, err = parseTokenConstraints(c)
		if err == nil {
			t.Fatalf("parseTokenConstraints: %v", err)
		}
	})
	t.Run("IllFormed", func(t *testing.T) {
		var err error
		c := ast.Array{ast.StringTerm("alg")}
		_, err = parseTokenConstraints(c)
		if err == nil {
			t.Fatalf("parseTokenConstraints: %v", err)
		}
	})
}

func TestParseTokenJWKS(t *testing.T) {
	t.Run("Text", func(t *testing.T) {
		var constraints tokenConstraints
		var err error
		c := ast.NewObject()
		c.Insert(ast.StringTerm("jwks"), ast.StringTerm(`{
			"keys": [
				{
					"kid": "one",
					"kty":"EC",
					"crv":"P-256",
					"x":"z8J91ghFy5o6f2xZ4g8LsLH7u2wEpT2ntj8loahnlsE",
					"y":"7bdeXLH61KrGWRdh7ilnbcGQACxykaPKfmBccTHIOUo"
				},
				{
					"kid": "two",
					"kty":"RSA",
					"e":"AQAB",
					"n":"uJApsyzFv-Y85M5JjezHvMDw_spgVCI7BqpYhnzK3xXw1dnkz1bWXGA9yF6AeADlE-1yc1ozrAURTnFSihIgj414i3MC2_0FkNcdAbnX7d9q9_jdCkHda4HER0zzXCaHlgnzoAz6edUU800-h0LleLnfgg4UST-0DFTCIGpfTbs7OPSy2WgT1vP6xbB45CUOJA7o0q6XE-hdhWWN0plrDiYD-0Y1SpOQYXmHhSmr-WVeKeoh5_0zeEVab6TQYec_16ByEyepaZB0g6WyGkFE6aG1NrpvDd24s_h7BAJg_S2mtu1lKWEqYjOgwzEl5XQQyXbpnq1USb12ArX16rZdew"
				}
			]
		}`))
		constraints, err = parseTokenConstraints(c)
		if err != nil {
			t.Fatalf("parseTokenConstraints: %v", err)
		}
		ecKey := constraints.jwks["one"].(*ecdsa.PublicKey)
		if ecKey.Curve != elliptic.P256() {
			t.Errorf("curve: %v", ecKey.Curve)
		}
		if ecKey.X.Text(16) != "cfc27dd60845cb9a3a7f6c59e20f0bb0b1fbbb6c04a53da7b63f25a1a86796c1" {
			t.Errorf("x: %x", ecKey.X)
		}
		if ecKey.Y.Text(16) != "edb75e5cb1fad4aac6591761ee29676dc190002c7291a3ca7e605c7131c8394a" {
			t.Errorf("y: %x", ecKey.Y)
		}
		rsaKey := constraints.jwks["two"].(*rsa.PublicKey)
		if rsaKey.E != 65537 {
			t.Errorf("x: %x", rsaKey.E)
		}
		if rsaKey.N.Text(16) != "b89029b32cc5bfe63ce4ce498decc7bcc0f0feca6054223b06aa58867ccadf15f0d5d9e4cf56d65c603dc85e807800e513ed72735a33ac05114e71528a12208f8d788b7302dbfd0590d71d01b9d7eddf6af7f8dd0a41dd6b81c4474cf35c26879609f3a00cfa79d514f34d3e8742e578b9df820e14493fb40c54c2206a5f4dbb3b38f4b2d96813d6f3fac5b078e4250e240ee8d2ae9713e85d85658dd2996b0e2603fb46354a93906179878529abf9655e29ea21e7fd3378455a6fa4d061e73fd7a0721327a969907483a5b21a4144e9a1b536ba6f0dddb8b3f87b040260fd2da6b6ed6529612a6233a0c33125e57410c976e99ead5449bd7602b5f5eab65d7b" {
			t.Errorf("n: %x", rsaKey.N)
		}
	})
	t.Run("Object", func(t *testing.T) {
		var constraints tokenConstraints
		var err error
		var jwks ast.Value
		if jwks, err = ast.InterfaceToValue(map[string]interface{}{
			"keys": []interface{}{
				map[string]interface{}{
					"kid": "one",
					"kty": "EC",
					"crv": "P-256",
					"x":   "z8J91ghFy5o6f2xZ4g8LsLH7u2wEpT2ntj8loahnlsE",
					"y":   "7bdeXLH61KrGWRdh7ilnbcGQACxykaPKfmBccTHIOUo",
				},
			},
		}); err != nil {
			t.Fatalf("ast.InterfaceToValue: %v", err)
		}
		c := ast.NewObject()
		c.Insert(ast.StringTerm("jwks"), &ast.Term{Value: jwks, Location: nil})
		constraints, err = parseTokenConstraints(c)
		if err != nil {
			t.Fatalf("parseTokenConstraints: %v", err)
		}
		ecKey := constraints.jwks["one"].(*ecdsa.PublicKey)
		if ecKey.Curve != elliptic.P256() {
			t.Errorf("curve: %v", ecKey.Curve)
		}
		if ecKey.X.Text(16) != "cfc27dd60845cb9a3a7f6c59e20f0bb0b1fbbb6c04a53da7b63f25a1a86796c1" {
			t.Errorf("x: %x", ecKey.X)
		}
		if ecKey.Y.Text(16) != "edb75e5cb1fad4aac6591761ee29676dc190002c7291a3ca7e605c7131c8394a" {
			t.Errorf("y: %x", ecKey.Y)
		}
	})
	t.Run("Malformed", func(t *testing.T) {
		var err error
		c := ast.NewObject()
		c.Insert(ast.StringTerm("jwks"), ast.StringTerm(`{
			"keys": [
				{
					"kid": "one",
					"kty":"EC",
					`))
		_, err = parseTokenConstraints(c)
		if err == nil {
			t.Fatalf("parseTokenConstraints: %v", err)
		}

	})
	t.Run("Invalid", func(t *testing.T) {
		var err error
		c := ast.NewObject()
		c.Insert(ast.StringTerm("jwks"), ast.StringTerm(`{
			"keys": [
				{
					"kty":"EC",
					"crv":"P-256",
					"x":"z8J91ghFy5o6f2xZ4g8LsLH7u2wEpT2ntj8loahnlsE",
					"y":"7bdeXLH61KrGWRdh7ilnbcGQACxykaPKfmBccTHIOUo"
				}
			]
		}`))
		_, err = parseTokenConstraints(c)
		if err == nil {
			t.Fatalf("parseTokenConstraints: %v", err)
		}

	})

}

func TestParseTokenHeader(t *testing.T) {
	t.Run("Errors", func(t *testing.T) {
		token := &JSONWebToken{
			header: "",
		}
		var err error
		if err = token.decodeHeader(); err == nil {
			t.Fatalf("token.decodeHeader: %v", err)
		}
		token.header = "###"
		if err = token.decodeHeader(); err == nil {
			t.Fatalf("token.decodeHeader: %v", err)
		}
		token.header = base64.RawURLEncoding.EncodeToString([]byte(`{`))
		if err = token.decodeHeader(); err == nil {
			t.Fatalf("token.decodeHeader: %v", err)
		}
		token.header = base64.RawURLEncoding.EncodeToString([]byte(`{}`))
		if err = token.decodeHeader(); err != nil {
			t.Fatalf("token.decodeHeader: %v", err)
		}
		var header tokenHeader
		header, err = parseTokenHeader(token)
		if err != nil {
			t.Fatalf("parseTokenHeader: %v", err)
		}
		if header.valid() {
			t.Fatalf("tokenHeader valid")
		}
	})
	t.Run("Alg", func(t *testing.T) {
		token := &JSONWebToken{
			header: base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`)),
		}
		var err error
		if err = token.decodeHeader(); err != nil {
			t.Fatalf("token.decodeHeader: %v", err)
		}
		var header tokenHeader
		header, err = parseTokenHeader(token)
		if err != nil {
			t.Fatalf("parseTokenHeader: %v", err)
		}
		if !header.valid() {
			t.Fatalf("tokenHeader !valid")
		}
		if header.alg != "RS256" {
			t.Fatalf("alg: %s", header.alg)
		}
	})
}
