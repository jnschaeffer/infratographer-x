// Package tokenexchange implements the OAuth 2.0 RFC 8693 Token Exchange flow.
//
// This should be used when interacting with a service that allows the exchange of
// tokens from one security domain (e.g., another OAuth 2.0 authorization server)
// for tokens valid in the target authorization server's security domain.
//
// See https://www.rfc-editor.org/rfc/rfc8693.html
package tokenexchange

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

const (
	paramSubjectToken     = "subject_token"
	paramSubjectTokenType = "subject_token_type"
	paramGrantType        = "grant_type"

	grantTypeExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
)

const (
	// SubjectTokenTypeJWT represents a JWT subject token type.
	SubjectTokenTypeJWT = "urn:ietf:params:oauth:token-type:jwt"
)

type tokenExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
}

// Config represents a configuration for a STS-based token source.
type Config struct {
	// ClientID is the application's ID. Optional.
	ClientID string

	// ClientSecret is the application's secret. Optional.
	ClientSecret string

	// SubjectTokenType represents the type of the subject token to send to the security token
	// service.
	SubjectTokenType string

	// TokenURL is the URL for the security token service token endpoint.
	TokenURL string
}

// TokenSource creates a token source that exchanges the token issued by the provided token source
// for one issued by the configured security token service.
func (c *Config) TokenSource(ctx context.Context, orig oauth2.TokenSource) oauth2.TokenSource {
	tokenSrc := &tokenSource{
		ctx:              ctx,
		clientID:         c.ClientID,
		clientSecret:     c.ClientSecret,
		subjectTokenType: c.SubjectTokenType,
		tokenURL:         c.TokenURL,
	}

	return oauth2.ReuseTokenSource(nil, tokenSrc)
}

type tokenSource struct {
	ctx              context.Context
	clientID         string
	clientSecret     string
	tokenURL         string
	subjectTokenType string
	origSrc          oauth2.TokenSource
}

func (t *tokenSource) Token() (*oauth2.Token, error) {
	return t.exchangeToken()
}

func getHTTPClient(ctx context.Context) *http.Client {
	maybeClient := ctx.Value(oauth2.HTTPClient)
	if maybeClient != nil {
		return maybeClient.(*http.Client)
	}

	return http.DefaultClient
}

func buildTokenFromResponse(resp *http.Response) (*oauth2.Token, error) {
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var tokenResponse tokenExchangeResponse

	if err := json.Unmarshal(bodyBytes, &tokenResponse); err != nil {
		return nil, err
	}

	var out oauth2.Token

	out.AccessToken = tokenResponse.AccessToken
	out.TokenType = tokenResponse.TokenType
	out.Expiry = time.Now().Add(time.Duration(tokenResponse.ExpiresIn) * time.Second)

	return &out, nil
}

func (t *tokenSource) buildExchangeRequest() (*http.Request, error) {
	token, err := t.origSrc.Token()
	if err != nil {
		return nil, err
	}

	values := url.Values{}

	values.Set(paramGrantType, grantTypeExchange)
	values.Set(paramSubjectToken, token.AccessToken)
	values.Set(paramSubjectTokenType, t.subjectTokenType)

	valuesReader := strings.NewReader(values.Encode())

	return http.NewRequestWithContext(t.ctx, http.MethodPost, t.tokenURL, valuesReader)
}

func (t *tokenSource) exchangeToken() (*oauth2.Token, error) {
	request, err := t.buildExchangeRequest()
	if err != nil {
		return nil, err
	}

	client := getHTTPClient(t.ctx)

	resp, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	return buildTokenFromResponse(resp)
}
