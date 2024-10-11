package go_jwt_kc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
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
	"strings"
	"time"
)

var jwksCache *cache.Cache

type KeyDTO struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type CachedKey struct {
	Kid          string
	Kty          string
	Alg          string
	Use          string
	RSAPublicKey *rsa.PublicKey
	ECPublicKey  *ecdsa.PublicKey
}

type JwksDTO struct {
	Keys []KeyDTO `json:"keys"`
}

type JWKS struct {
	Keys map[string]CachedKey
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

func createCachedKeyFromDTO(key *KeyDTO, kong *pdk.PDK) (*CachedKey, error) {
	cachedKey := &CachedKey{
		Kid: key.Kid,
		Kty: key.Kty,
		Alg: key.Alg,
		Use: key.Use,
	}

	if strings.HasPrefix(key.Alg, "RS") {
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

		cachedKey.RSAPublicKey = &rsa.PublicKey{
			N: big.NewInt(0).SetBytes(decodedN),
			E: int(big.NewInt(0).SetBytes(decodedE).Int64()),
		}
	} else if strings.HasPrefix(key.Alg, "ES") {
		// decode base64 url encoded X and Y
		decodedX, err := base64.RawURLEncoding.DecodeString(key.X)
		if err != nil {
			_ = kong.Log.Err("Error decoding base64 url encoded X (" + key.X + "): " + err.Error())
			return nil, fmt.Errorf("error decoding base64 url encoded X: %s", err)
		}
		intX := big.NewInt(0).SetBytes(decodedX)

		decodedY, err := base64.RawURLEncoding.DecodeString(key.Y)
		if err != nil {
			_ = kong.Log.Err("Error decoding base64 url encoded Y (" + key.Y + "): " + err.Error())
			return nil, fmt.Errorf("error decoding base64 url encoded Y: %s", err)
		}
		intY := big.NewInt(0).SetBytes(decodedY)

		cachedKey.ECPublicKey = &ecdsa.PublicKey{
			X: intX,
			Y: intY,
		}

		var curve elliptic.Curve
		switch key.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported elliptic curve %s", key.Crv)
		}

		cachedKey.ECPublicKey.Curve = curve

	} else {
		_ = kong.Log.Err("Unsupported algorithm " + key.Alg + " for key with kid " + key.Kid)
		return nil, nil
	}

	return cachedKey, nil
}

func retrieveJWKS(wellKnownEndpoint string, kong *pdk.PDK) (*JWKS, error) {
	// Check if JWKS is cached
	if cachedJWKS, found := jwksCache.Get(wellKnownEndpoint); found {
		return cachedJWKS.(*JWKS), nil
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
	var jwks JwksDTO
	err = json.NewDecoder(res.Body).Decode(&jwks)
	if err != nil {
		_ = kong.Log.Err("Error getting JWKS from " + wellKnownEndpoint + ": " + err.Error())
		return nil, fmt.Errorf("error getting JWKS from %s: %s", wellKnownEndpoint, err)
	}

	cachedJWKS := JWKS{
		Keys: make(map[string]CachedKey, len(jwks.Keys)),
	}

	for _, key := range jwks.Keys {
		cachedKey, err := createCachedKeyFromDTO(&key, kong)
		if err != nil {
			_ = kong.Log.Err(err.Error())
			return nil, err
		}
		if cachedKey != nil {
			_ = kong.Log.Debug("Successfully decoded public key from JWKS with kid " + key.Kid)
			cachedJWKS.Keys[key.Kid] = *cachedKey
		} else {
			_ = kong.Log.Err("Error decoding public key from JWKS with kid " + key.Kid)
		}
	}

	// Cache JWKS
	jwksCache.Set(wellKnownEndpoint, &cachedJWKS, cache.DefaultExpiration)

	return &cachedJWKS, nil
}
