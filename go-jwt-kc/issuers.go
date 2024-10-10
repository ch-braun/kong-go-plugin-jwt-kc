package go_jwt_kc

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/Kong/go-pdk"
	"github.com/patrickmn/go-cache"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"time"
)

var jwksCache *cache.Cache

type Key struct {
	Kid       string         `json:"kid"`
	Kty       string         `json:"kty"`
	Alg       string         `json:"alg"`
	Use       string         `json:"use"`
	N         string         `json:"n"`
	E         string         `json:"e"`
	PublicKey *rsa.PublicKey `json:"public_key"`
}

type JWKS struct {
	Keys []Key `json:"keys"`
}

func init() {
	// Adjust JWKS cache expiration if environment variable is present
	expiration := 3600 * 6 // default = 6h

	if envExpiration := os.Getenv("KONG_PLUGIN_CONFIG_JWT_GO_JWKS_CACHE_EXPIRATION"); envExpiration != "" {
		var err error
		expiration, err = strconv.Atoi(envExpiration)

		if err != nil {
			log.Fatalf(
				"Error converting KONG_PLUGIN_CONFIG_JWT_GO_JWKS_CACHE_EXPIRATION=%s to int",
				envExpiration)
		}
	}

	jwksCache = cache.New(time.Duration(expiration)*time.Second, time.Duration(2*expiration)*time.Second)
}

func retrieveJWKS(wellKnownEndpoint string, kong *pdk.PDK) (*JWKS, error) {
	// Check if JWKS is cached
	if jwks, found := jwksCache.Get(wellKnownEndpoint); found {
		return jwks.(*JWKS), nil
	}
	_ = kong.Log.Debug("Getting public keys from token issuer " + wellKnownEndpoint)

	res, err := http.DefaultClient.Get(wellKnownEndpoint)
	if err != nil {
		_ = kong.Log.Err("Error getting JWKS from " + wellKnownEndpoint + ": " + err.Error())
		return nil, fmt.Errorf("error getting JWKS from %s: %s", wellKnownEndpoint, err)
	}
	// Read response body
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(res.Body)
	var result map[string]interface{}
	err = json.NewDecoder(res.Body).Decode(&result)
	if err != nil {
		_ = kong.Log.Err("Error getting JWKS from " + wellKnownEndpoint + ": " + err.Error())
		return nil, fmt.Errorf("error getting JWKS from %s: %s", wellKnownEndpoint, err)
	}

	// Fetch JWKS from well-known endpoint
	res, err = http.DefaultClient.Get(result["jwks_uri"].(string))
	if err != nil {
		_ = kong.Log.Err("Error getting JWKS from " + wellKnownEndpoint + ": " + err.Error())
		return nil, fmt.Errorf("error getting JWKS from %s: %s", wellKnownEndpoint, err)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(res.Body)
	var jwks JWKS
	err = json.NewDecoder(res.Body).Decode(&jwks)
	if err != nil {
		_ = kong.Log.Err("Error getting JWKS from " + wellKnownEndpoint + ": " + err.Error())
		return nil, fmt.Errorf("error getting JWKS from %s: %s", wellKnownEndpoint, err)
	}

	for i := range jwks.Keys {
		key := &jwks.Keys[i]
		// decode base64 url encoded N and E
		decodedN, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			_ = kong.Log.Err("Error decoding base64 url encoded N (" + key.N + "): " + err.Error())
			return nil, fmt.Errorf("error decoding base64 url encoded N: %s", err)
		}

		decodedE, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil {
			_ = kong.Log.Err("Error decoding base64 url encoded E (" + key.E + "): " + err.Error())
			return nil, fmt.Errorf("error decoding base64 url encoded E: %s", err)
		}

		key.PublicKey = &rsa.PublicKey{
			N: big.NewInt(0).SetBytes(decodedN),
			E: int(big.NewInt(0).SetBytes(decodedE).Int64()),
		}
		_ = kong.Log.Debug("Successfully decoded public key from JWKS with kid " + key.Kid)
	}

	// Cache JWKS
	jwksCache.Set(wellKnownEndpoint, &jwks, cache.DefaultExpiration)

	return &jwks, nil
}
