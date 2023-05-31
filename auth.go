package melon-auth-middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
)

// Config the plugin configuration.
type Config struct {
	IAM map[string]string
}

// Create the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		IAM: make(map[string]string),
	}
}

// AuthData a Traefik Authorization plugin.
type AuthData struct {
	next                   http.Handler
	name                   string
	config *Config
//	clientId               string
//	iamUrl                 string
//	usernameParam     string
//	passwordParam string
}

type KeycloakResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	TokenType        string `json:"token_type"`
	NotBeforePolicy  int    `json:"not-before-policy"`
	SessionState     string `json:"session_state"`
	Scope            string `json:"scope"`
}

// Create an instance of the plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.IAM) != 4 {
		return nil, fmt.Errorf("IAM Configuration must be defined")
	}

	return &AuthData{
		next:                   next,
		name:                   name,
		config: config
//		clientId:               config.IAM["ClientId"],
//		iamUrl:                 config.IAM["Url"],
//		userQueryParamName:     config.IAM["usernameParam"],
//		passwordQueryParamName: config.IAM["passwordParam"],
	}, nil
}

func (ad *AuthData) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	query := req.URL.Query()
	username, usernamePresent := query[ad.config.IAM["usernameParam"]
	password, passwordPresent := query[ad.config.IAM["passwordParam"]

	if !usernamePresent || !passwordPresent {
		http.Error(rw, "MalformedQuery", http.StatusBadRequest)
		return
	}

	authResponse, err := http.PostForm(ad.iamUrl,
		url.Values{
			"grant_type": {"password"},
			"client_id":  {ad.config.IAM["ClientId"]},
			"client_secret":  {ad.config.IAM["ClientSecret"]},
			"username":   {username[0]},
			"password":   {password[0]},
		})

	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	if authResponse.StatusCode != http.StatusOK {
		http.Error(rw, "Forbidden", http.StatusUnauthorized)
		return
	}

	body, err := ioutil.ReadAll(authResponse.Body)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	var result KeycloakResponse
	err = json.Unmarshal(body, &result)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", result.AccessToken))
	cerbereConfig.next.ServeHTTP(rw, req)
}
