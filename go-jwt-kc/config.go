package go_jwt_kc

type Config struct {
	UriParamNames               string `json:"uri_param_names"`
	CookieNames                 string `json:"cookie_names"`
	ClaimsToVerify              string `json:"claims_to_verify"`
	Anonymous                   string `json:"anonymous"`
	RunOnPreflight              bool   `json:"run_on_preflight"`
	HeaderNames                 string `json:"header_names"`
	MaximumExpiration           int64  `json:"maximum_expiration"`
	Algorithms                  string `json:"algorithms"`
	AllowedIss                  string `json:"allowed_iss"`
	WellKnownTemplate           string `json:"well_known_template"`
	Scope                       string `json:"scope"`
	Roles                       string `json:"roles"`
	RealmRoles                  string `json:"realm_roles"`
	ClientRoles                 string `json:"client_roles"`
	ConsumerMatch               bool   `json:"consumer_match"`
	ConsumerMatchClaim          string `json:"consumer_match_claim"`
	ConsumerMatchIgnoreNotFound bool   `json:"consumer_match_ignore_not_found"`
}

func New() interface{} {
	return &Config{}
}
