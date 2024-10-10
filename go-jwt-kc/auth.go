package go_jwt_kc

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/Kong/go-pdk"
	"github.com/Kong/go-pdk/client"
	"github.com/Kong/go-pdk/entities"
	"github.com/golang-jwt/jwt/v4"
	"github.com/patrickmn/go-cache"
	"maps"
	"net/http"
	"strings"
	"time"
)

const (
	HeaderConsumerId           = "X-Consumer-ID"
	HeaderConsumerCustomId     = "X-Consumer-Custom-ID"
	HeaderConsumerUsername     = "X-Consumer-Username"
	HeaderCredentialIdentifier = "X-Credential-Identifier"
	HeaderAnonymous            = "X-Anonymous-Consumer"
)

type authError struct {
	message    string
	statusCode int
	err        error
}

var consumerCache = cache.New(5*time.Minute, 10*time.Minute)

func doAuthentication(conf *Config, kong *pdk.PDK) (bool, *authError) {
	tokens, err := retrieveTokens(conf, kong)
	if err != nil {
		_ = kong.Log.Err("Error while authentication: " + err.Error())
		return false, &authError{"An unexpected error occurred", http.StatusInternalServerError, err}
	}

	if len(tokens) == 0 {
		return false, &authError{"Unauthorized", http.StatusUnauthorized, nil}
	}

	if len(tokens) > 1 {
		return false, &authError{"Multiple tokens provided", http.StatusUnauthorized, nil}
	}

	// Decode token to find out who the consumer is
	tokens[0] = strings.ReplaceAll(tokens[0], "Bearer ", "")
	tokens[0] = strings.ReplaceAll(tokens[0], "bearer ", "")
	parsedJWT, _, err := jwt.NewParser().ParseUnverified(tokens[0], jwt.MapClaims{})

	if err != nil {
		_ = kong.Log.Err("Error while parsing JWT: " + err.Error())
		return false, &authError{"Bad token; " + err.Error(), http.StatusUnauthorized, err}
	}

	claims := parsedJWT.Claims.(jwt.MapClaims)
	header := parsedJWT.Header

	// Verify that the issuer is allowed
	issOk := false
	for _, iss := range strings.Split(conf.AllowedIss, ",") {
		if iss == claims["iss"].(string) {
			issOk = true
			break
		}
	}
	if !issOk {
		return false, &authError{"Token issuer not allowed", http.StatusUnauthorized, nil}
	}

	// Verify that the algorithm is allowed
	configuredAlgorithm := strings.ToUpper(conf.Algorithm)
	if configuredAlgorithm == "" {
		configuredAlgorithm = "HS256"
	}
	if header["alg"] != configuredAlgorithm {
		return false, &authError{"Invalid algorithm", http.StatusForbidden, nil}
	}

	// Now verify the JWT signature
	method := jwt.GetSigningMethod(configuredAlgorithm)
	if method == nil {
		return false, &authError{"Invalid algorithm", http.StatusForbidden, nil}
	}

	// Split the token into parts
	parts := strings.Split(tokens[0], ".")
	if len(parts) != 3 {
		return false, &authError{"Bad token", http.StatusUnauthorized, nil}
	}
	_, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false, &authError{"Bad token", http.StatusUnauthorized, err}
	}

	// Retrieve the JWKS
	jwks, err := retrieveJWKS(fmt.Sprintf(conf.WellKnownTemplate, claims["iss"]), kong)
	if err != nil {
		return false, &authError{"Error getting JWKS", http.StatusInternalServerError, err}
	}
	valid := false
	for _, key := range jwks.Keys {
		if key.Kid == header["kid"] {
			_ = kong.Log.Debug("Verifying signature with key " + key.Kid)
			if err = method.Verify(parts[0]+"."+parts[1], parts[2], key.PublicKey); err == nil {
				_ = kong.Log.Debug("Signature successfully verified with key " + key.Kid)
				valid = true
				break
			} else {
				_ = kong.Log.Debug("Error verifying signature with key " + key.Kid + ": " + err.Error())
			}
		}
	}

	if !valid {
		return false, &authError{"Invalid signature", http.StatusUnauthorized, nil}
	}

	//Verify the JWT registered claims
	for _, claim := range strings.Split(strings.ToLower(conf.ClaimsToVerify), ",") {
		if claims[claim] == nil {
			return false, &authError{"Missing claim " + claim, http.StatusUnauthorized, nil}
		}
	}

	// Check if the token is expired
	if conf.MaximumExpiration > 0 {
		if !claims.VerifyExpiresAt(time.Now().Unix()-conf.MaximumExpiration, true) {
			return false, &authError{"Token expired", http.StatusForbidden, nil}
		}
	}

	// Match the consumer
	ok, err := matchConsumer(conf, kong, claims)
	if err != nil {
		return false, nil
	}
	if !ok {
		return false, &authError{"Consumer does not match", http.StatusForbidden, nil}
	}

	// Verify roles or scopes
	// Validate scopes
	ok, err = validateScope(strings.Split(conf.Scope, ","), &claims)

	// Validate realm roles
	if ok {
		ok, err = validateRealmRoles(strings.Split(conf.RealmRoles, ","), &claims)
	}

	// Validate roles
	if ok {
		ok, err = validateRoles(strings.Split(conf.Roles, ","), &claims)
	}

	// Validate client roles
	if ok {
		ok, err = validateClientRoles(strings.Split(conf.ClientRoles, ","), &claims)
	}

	if ok {
		_ = kong.Ctx.SetShared("jwt_keycloak_token", parsedJWT)
		return true, nil
	}

	return false, &authError{"Access token does not have the required scope/role: ", http.StatusForbidden, err}
}

// retrieveToken Retrieve a JWT in a request.
// Checks for the JWT in URI parameters, then in cookies, and finally
// in the configured header_names (defaults to `[Authorization]`).
// @param conf The Plugin configuration
// @param kong The Kong context
// @return token The JWT token contained in request (can be a table) or nil
// @return err
func retrieveTokens(conf *Config, kong *pdk.PDK) ([]string, error) {
	tokenSet := make(map[string]bool)

	// Fetch JWT from uri params
	args, err := kong.Request.GetQuery(-1)
	if err != nil {
		_ = kong.Log.Err("Error while fetching JWT from uri params: " + err.Error())
		return nil, err
	}
	for _, param := range strings.Split(strings.ToLower(conf.UriParamNames), ",") {
		if param == "" {
			continue
		}
		if tokens, found := args[param]; found && tokens != nil {
			for _, t := range tokens {
				if t != "" {
					tokenSet[t] = true
				}
			}
		}
	}

	// Fetch JWT from cookies
	for _, cookieName := range strings.Split(conf.CookieNames, ",") {
		cookie, err := kong.Nginx.GetVar("cookie_" + cookieName)
		if err != nil {
			_ = kong.Log.Err("Error while fetching JWT from cookies: " + err.Error())
			return nil, err
		}
		if cookie != "" {
			tokenSet[cookie] = true
		}
	}

	// Fetch JWT from request headers
	requestHeaders, err := kong.Request.GetHeaders(-1)
	if err != nil {
		_ = kong.Log.Err("Error while fetching JWT from request headers: " + err.Error())
		return nil, err
	}
	for _, headerName := range strings.Split(strings.ToLower(conf.HeaderNames), ",") {
		if tokens, found := requestHeaders[headerName]; found && tokens != nil {
			for _, t := range tokens {
				if t != "" {
					tokenSet[t] = true
				}
			}
		}
	}

	// Convert "set" back to slice
	tokenSlice := make([]string, 0, len(tokenSet))
	for k := range maps.Keys(tokenSet) {
		tokenSlice = append(tokenSlice, k)
	}
	return tokenSlice, nil
}

func matchConsumer(conf *Config, kong *pdk.PDK, claims jwt.MapClaims) (bool, error) {
	if !conf.ConsumerMatch {
		return true, nil
	}
	_ = kong.Log.Debug("Matching consumer")
	consumerId := claims[strings.ToLower(conf.ConsumerMatchClaim)]
	consumer, err := fetchConsumer(consumerId.(string), kong)
	if err != nil {
		_ = kong.Log.Err("Error while fetching consumer: " + err.Error())
		return false, err
	}

	if consumer.Id == "" && !conf.ConsumerMatchIgnoreNotFound {
		_ = kong.Log.Debug("Unable to find consumer " + consumerId.(string) + " for token")
		return false, nil
	}

	if consumer.Id != "" {
		setConsumer(consumer, nil, nil, kong)
	}

	return true, nil
}

func fetchConsumer(consumerId string, kong *pdk.PDK) (*entities.Consumer, error) {
	cachedConsumer, found := consumerCache.Get(consumerId)
	if found {
		return cachedConsumer.(*entities.Consumer), nil
	}

	consumer, err := kong.Client.LoadConsumer(consumerId, true)
	if err != nil {
		_ = kong.Log.Err("Error while fetching consumer: " + err.Error())
		return nil, err
	}

	consumerCache.Set(consumerId, &consumer, cache.DefaultExpiration)
	return &consumer, nil
}

func setConsumer(consumer *entities.Consumer, credential *client.AuthenticatedCredential, token *jwt.Token, kong *pdk.PDK) {
	_ = kong.Client.Authenticate(consumer, credential)

	if consumer != nil && consumer.Id != "" {
		_ = kong.ServiceRequest.SetHeader(HeaderConsumerId, consumer.Id)
	} else {
		_ = kong.ServiceRequest.ClearHeader(HeaderConsumerId)
	}

	if consumer != nil && consumer.CustomId != "" {
		_ = kong.Log.Debug("found consumer " + consumer.CustomId)
		_ = kong.ServiceRequest.SetHeader(HeaderConsumerCustomId, consumer.CustomId)
	} else {
		_ = kong.ServiceRequest.ClearHeader(HeaderConsumerCustomId)
	}

	if consumer != nil && consumer.Username != "" {
		_ = kong.ServiceRequest.SetHeader(HeaderConsumerUsername, consumer.Username)
	} else {
		_ = kong.ServiceRequest.ClearHeader(HeaderConsumerUsername)
	}

	if credential != nil && credential.Id != "" {
		_ = kong.ServiceRequest.SetHeader(HeaderCredentialIdentifier, credential.Id)
	} else {
		_ = kong.ServiceRequest.ClearHeader(HeaderCredentialIdentifier)
	}

	if credential != nil {
		_ = kong.ServiceRequest.ClearHeader(HeaderAnonymous)
	} else {
		_ = kong.ServiceRequest.SetHeader(HeaderAnonymous, "true")
	}

	_ = kong.Nginx.SetCtx("authenticated_jwt_token", token)
	_ = kong.Ctx.SetShared("authenticated_jwt_token", token)
}

func validateScope(allowedScopes []string, claims *jwt.MapClaims) (bool, error) {
	if allowedScopes == nil || len(allowedScopes) == 0 || allowedScopes[0] == "" {
		return true, nil
	}

	scopes, ok := (*claims)["scope"]
	if !ok {
		return false, errors.New("missing scope claim")
	}

	for _, scope := range allowedScopes {
		if strings.Contains(scopes.(string), scope) {
			return true, nil
		}
	}

	return false, errors.New("missing required scope")
}

func validateRealmRoles(allowedRealmRoles []string, claims *jwt.MapClaims) (bool, error) {
	if allowedRealmRoles == nil || len(allowedRealmRoles) == 0 || allowedRealmRoles[0] == "" {
		return true, nil
	}

	claimAccess, ok := (*claims)["realm_access"].(map[string][]string)
	if !ok {
		return false, errors.New("missing required realm_access claim")
	}

	if _, ok := claimAccess["roles"]; !ok {
		return false, errors.New("missing required realm_access.roles claim")
	}

	for _, claimRole := range claimAccess["roles"] {
		for _, allowedRole := range allowedRealmRoles {
			if claimRole == allowedRole {
				return true, nil
			}
		}
	}

	return false, errors.New("missing required realm role")
}

func validateRoles(allowedRoles []string, claims *jwt.MapClaims) (bool, error) {
	if allowedRoles == nil || len(allowedRoles) == 0 || allowedRoles[0] == "" {
		return true, nil
	}

	azp, ok := (*claims)["azp"].(string)
	if !ok {
		return false, errors.New("missing azp claim")
	}

	claimRoles, ok := (*claims)["realm_access"].(map[string][]string)
	if !ok {
		return false, errors.New("missing required realm_access claim")
	}

	tmpAllowedRoles := make([]string, len(allowedRoles))
	for i, role := range claimRoles["roles"] {
		tmpAllowedRoles[i] = azp + ":" + role
	}

	return validateClientRoles(tmpAllowedRoles, claims)
}

func validateClientRoles(allowedClientRoles []string, claims *jwt.MapClaims) (bool, error) {
	if allowedClientRoles == nil || len(allowedClientRoles) == 0 || allowedClientRoles[0] == "" {
		return true, nil
	}

	claimRoles, ok := (*claims)["resource_access"].(map[string][]string)
	if !ok {
		return false, errors.New("missing required resource_access claim")
	}

	for _, allowedClientRole := range allowedClientRoles {
		split := strings.Split(allowedClientRole, ":")
		allowedClient := split[0]
		allowedRole := split[1]
		for claimClient, clientRoles := range claimRoles {
			if claimClient == allowedClient {
				for _, role := range clientRoles {
					if role == allowedRole {
						return true, nil
					}
				}
			}
		}
	}

	return false, errors.New("missing required role")
}
