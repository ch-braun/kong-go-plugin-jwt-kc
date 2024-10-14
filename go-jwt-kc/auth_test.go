package go_jwt_kc

import (
	"github.com/golang-jwt/jwt/v4"
	"testing"
)

func TestDoAuthentication(t *testing.T) {

}

func TestRetrieveToken(t *testing.T) {

}

func TestMatchConsumer(t *testing.T) {

}

func TestFetchConsumer(t *testing.T) {

}

func TestSetConsumer(t *testing.T) {

}

func TestValidateScope(t *testing.T) {
	tests := []struct {
		name           string
		allowedScopes  []string
		claims         jwt.MapClaims
		expectedResult bool
		expectedErrMsg string
	}{
		{
			name:          "valid scope",
			allowedScopes: []string{"scope1"},
			claims: jwt.MapClaims{
				"scope": "scope1",
			},
			expectedResult: true,
			expectedErrMsg: "",
		},
		{
			name:          "valid scope (multiple scopes in claims)",
			allowedScopes: []string{"scope1"},
			claims: jwt.MapClaims{
				"scope": "scope1 scope2",
			},
			expectedResult: true,
			expectedErrMsg: "",
		},
		{
			name:           "no scopes to check (nil)",
			allowedScopes:  nil,
			claims:         jwt.MapClaims{},
			expectedResult: true,
			expectedErrMsg: "",
		},
		{
			name:           "no scopes to check (zero-length)",
			allowedScopes:  []string{},
			claims:         jwt.MapClaims{},
			expectedResult: true,
			expectedErrMsg: "",
		},
		{
			name:           "no scopes to check (empty scope)",
			allowedScopes:  []string{""},
			claims:         jwt.MapClaims{},
			expectedResult: true,
			expectedErrMsg: "",
		},
		{
			name:          "Missing required scope",
			allowedScopes: []string{"scope2"},
			claims: jwt.MapClaims{
				"scope": "scope1 scope3",
			},
			expectedResult: false,
			expectedErrMsg: "missing required scope",
		},
		{
			name:           "Missing scope claim",
			allowedScopes:  []string{"scope1"},
			claims:         jwt.MapClaims{},
			expectedResult: false,
			expectedErrMsg: "missing required scope claim",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := validateScope(tt.allowedScopes, &tt.claims)
			if result != tt.expectedResult {
				t.Errorf("Expected %v, got %v", tt.expectedResult, result)
			}
			if err != nil && err.Error() != tt.expectedErrMsg {
				t.Errorf("Expected %v, got %v", tt.expectedErrMsg, err.Error())
			}
		})
	}
}

func TestValidateRealmRoles(t *testing.T) {
	tests := []struct {
		name              string
		allowedRealmRoles []string
		claims            jwt.MapClaims
		expectedResult    bool
		expectedErrMsg    string
	}{
		{
			name:              "valid realm role",
			allowedRealmRoles: []string{"role1"},
			claims: jwt.MapClaims{
				"realm_access": map[string][]string{
					"roles": {"role1"},
				},
			},
			expectedResult: true,
			expectedErrMsg: "",
		},
		{
			name:              "valid realm role (multiple roles in claims)",
			allowedRealmRoles: []string{"role1"},
			claims: jwt.MapClaims{
				"realm_access": map[string][]string{
					"roles": {"role1", "role2"},
				},
			},
			expectedResult: true,
			expectedErrMsg: "",
		},
		{
			name:              "no realm roles to check (nil)",
			allowedRealmRoles: nil,
			claims:            jwt.MapClaims{},
			expectedResult:    true,
			expectedErrMsg:    "",
		},
		{
			name:              "no realm roles to check (zero-length)",
			allowedRealmRoles: []string{},
			claims:            jwt.MapClaims{},
			expectedResult:    true,
			expectedErrMsg:    "",
		},
		{
			name:              "no realm roles to check (empty role)",
			allowedRealmRoles: []string{""},
			claims:            jwt.MapClaims{},
			expectedResult:    true,
			expectedErrMsg:    "",
		},
		{
			name:              "Missing required realm role",
			allowedRealmRoles: []string{"role2"},
			claims: jwt.MapClaims{
				"realm_access": map[string][]string{
					"roles": {"role1", "role3"},
				},
			},
			expectedResult: false,
			expectedErrMsg: "missing required realm role",
		},
		{
			name:              "Missing required realm_access claim",
			allowedRealmRoles: []string{"role1"},
			claims:            jwt.MapClaims{},
			expectedResult:    false,
			expectedErrMsg:    "missing required realm_access claim",
		},
		{
			name:              "Missing required realm_access.roles claim",
			allowedRealmRoles: []string{"role1"},
			claims: jwt.MapClaims{
				"realm_access": map[string][]string{},
			},
			expectedResult: false,
			expectedErrMsg: "missing required realm_access.roles claim",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := validateRealmRoles(tt.allowedRealmRoles, &tt.claims)
			if result != tt.expectedResult {
				t.Errorf("Expected %v, got %v", tt.expectedResult, result)
			}
			if err != nil && err.Error() != tt.expectedErrMsg {
				t.Errorf("Expected %v, got %v", tt.expectedErrMsg, err.Error())
			}
		})
	}
}

func TestValidateRoles(t *testing.T) {
	tests := []struct {
		name           string
		allowedRoles   []string
		claims         jwt.MapClaims
		expectedResult bool
		expectedErrMsg string
	}{
		{
			name:         "valid role",
			allowedRoles: []string{"role1"},
			claims: jwt.MapClaims{
				"resource_access": map[string][]string{
					"client1": {"role1", "role2"},
				},
				"azp": "client1",
			},
			expectedResult: true,
			expectedErrMsg: "",
		},
		{
			name:         "valid role (multiple clients in claims)",
			allowedRoles: []string{"role1"},
			claims: jwt.MapClaims{
				"resource_access": map[string][]string{
					"client1": {"role1", "role2"},
					"client2": {"role1", "role2"},
				},
				"azp": "client1",
			},
			expectedResult: true,
			expectedErrMsg: "",
		},
		{
			name:           "no roles to check (nil)",
			allowedRoles:   nil,
			claims:         jwt.MapClaims{},
			expectedResult: true,
			expectedErrMsg: "",
		},
		{
			name:           "no roles to check (zero-length)",
			allowedRoles:   []string{},
			claims:         jwt.MapClaims{},
			expectedResult: true,
			expectedErrMsg: "",
		},
		{
			name:           "no roles to check (empty role)",
			allowedRoles:   []string{""},
			claims:         jwt.MapClaims{},
			expectedResult: true,
			expectedErrMsg: "",
		},
		{
			name:         "Missing required role",
			allowedRoles: []string{"role2"},
			claims: jwt.MapClaims{
				"resource_access": map[string][]string{
					"client1": {"role1", "role3"},
					"client2": {"role1"},
				},
				"azp": "client1",
			},
			expectedResult: false,
			expectedErrMsg: "missing required role",
		},
		{
			name:         "Missing required resource_access claim",
			allowedRoles: []string{"role1"},
			claims: jwt.MapClaims{
				"azp": "client1",
			},
			expectedResult: false,
			expectedErrMsg: "missing required resource_access claim",
		},
		{
			name:         "Missing required azp claim",
			allowedRoles: []string{"role1"},
			claims: jwt.MapClaims{
				"resource_access": map[string][]string{
					"client1": {"role1", "role2"},
				},
			},
			expectedResult: false,
			expectedErrMsg: "missing required azp claim",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := validateRoles(tt.allowedRoles, &tt.claims)
			if result != tt.expectedResult {
				t.Errorf("Expected %v, got %v", tt.expectedResult, result)
			}
			if err != nil && err.Error() != tt.expectedErrMsg {
				t.Errorf("Expected %v, got %v", tt.expectedErrMsg, err.Error())
			}
		})
	}
}

func TestValidateClientRoles(t *testing.T) {
	tests := []struct {
		name               string
		allowedClientRoles []string
		claims             jwt.MapClaims
		expectedResult     bool
		expectedErrMsg     string
	}{
		{
			name:               "valid client role",
			allowedClientRoles: []string{"client1:role1"},
			claims: jwt.MapClaims{
				"resource_access": map[string][]string{
					"client1": {"role1", "role2"},
				},
			},
			expectedResult: true,
			expectedErrMsg: "",
		},
		{
			name:               "valid client role (multiple clients in claims)",
			allowedClientRoles: []string{"client2:role1"},
			claims: jwt.MapClaims{
				"resource_access": map[string][]string{
					"client1": {"role1", "role2"},
					"client2": {"role1", "role2"},
				},
			},
			expectedResult: true,
			expectedErrMsg: "",
		},
		{
			name:               "no client roles to check (nil)",
			allowedClientRoles: nil,
			claims:             jwt.MapClaims{},
			expectedResult:     true,
			expectedErrMsg:     "",
		},
		{
			name:               "no client roles to check (zero-length)",
			allowedClientRoles: []string{},
			claims:             jwt.MapClaims{},
			expectedResult:     true,
			expectedErrMsg:     "",
		},
		{
			name:               "no client roles to check (empty role)",
			allowedClientRoles: []string{""},
			claims:             jwt.MapClaims{},
			expectedResult:     true,
			expectedErrMsg:     "",
		},
		{
			name:               "Missing required role",
			allowedClientRoles: []string{"client1:role2"},
			claims: jwt.MapClaims{
				"resource_access": map[string][]string{
					"client1": {"role1", "role3"},
					"client2": {"role1"},
				},
			},
			expectedResult: false,
			expectedErrMsg: "missing required role",
		},
		{
			name:               "Missing resource_access claim",
			allowedClientRoles: []string{"client1:role1"},
			claims:             jwt.MapClaims{},
			expectedResult:     false,
			expectedErrMsg:     "missing required resource_access claim",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := validateClientRoles(tt.allowedClientRoles, &tt.claims)
			if result != tt.expectedResult {
				t.Errorf("Expected %v, got %v", tt.expectedResult, result)
			}
			if err != nil && err.Error() != tt.expectedErrMsg {
				t.Errorf("Expected %v, got %v", tt.expectedErrMsg, err.Error())
			}
		})
	}
}
