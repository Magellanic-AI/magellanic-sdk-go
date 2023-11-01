package magellanic

import (
	"encoding/base64"
	"errors"
	"github.com/cloudflare/circl/sign/eddilithium2"
	"github.com/cloudflare/circl/sign/eddilithium3"
	"github.com/imroc/req/v3"
	"os"
	"sync"
	"time"
)

// TODO: http errors handling

const (
	ID_HEADER_NAME   = "magellanic-workload-id"
	AUTH_HEADER_NAME = "magellanic-authorization"
)

type Error struct {
	Message string
}

type Client struct {
	reqClient *req.Client

	Id string

	token               string
	tokenLock           sync.RWMutex
	tokenRotationQuitCh chan bool
	tokenPublicKey      []byte

	dilithiumMode       int
	dilithiumPrivateKey []byte

	ErrorCh chan Error
}

func (c *Client) startTokenRotation(firstTokenExpiryDate string) {
	countRotation := func(expiryDate string) time.Duration {
		ts, _ := time.Parse(time.RFC3339, expiryDate)
		return ts.Sub(time.Now().Add(10 * time.Second))
	}
	timer := time.NewTimer(countRotation(firstTokenExpiryDate))

	var rotateTokenResponse struct {
		Token           string `json:"token"`
		TokenExpiryDate string `json:"tokenExpiryDate"`
	}
	var rotateTokenPayload struct {
		Token     string `json:"token"`
		Signature string `json:"signature"`
	}

	for {
		select {
		case <-c.tokenRotationQuitCh:
			return
		case <-timer.C:
			rotateTokenPayload.Token = c.GetMyToken()
			rotateTokenPayload.Signature = c.DilithiumSign(rotateTokenPayload.Token)
			_, err := c.reqClient.R().
				SetBody(&rotateTokenPayload).
				SetSuccessResult(&rotateTokenResponse).
				Post("/rotate-token")

			if err != nil {
				go func() {
					c.ErrorCh <- Error{err.Error()}
				}()
				return
			}
			c.tokenLock.Lock()
			c.token = rotateTokenResponse.Token
			c.tokenLock.Unlock()
			timer.Reset(countRotation(rotateTokenResponse.TokenExpiryDate))
		}
	}
}

func (c *Client) GetMyToken() string {
	c.tokenLock.RLock()
	defer c.tokenLock.RUnlock()
	return c.token
}

func (c *Client) DilithiumSign(message string) string {
	messageBytes := []byte(message)
	if c.dilithiumMode == 2 {
		var signature [eddilithium2.SignatureSize]byte
		var privateKey eddilithium2.PrivateKey
		privateKey.Unpack((*[2560]byte)(c.dilithiumPrivateKey))
		eddilithium2.SignTo(&privateKey, messageBytes, signature[:])
		return base64.StdEncoding.EncodeToString(signature[:])
	} else {
		var signature [eddilithium3.SignatureSize]byte
		var privateKey eddilithium3.PrivateKey
		privateKey.Unpack((*[4057]byte)(c.dilithiumPrivateKey))
		eddilithium3.SignTo(&privateKey, messageBytes, signature[:])
		return base64.StdEncoding.EncodeToString(signature[:])
	}
}

func (c *Client) DilithiumVerify(message string, signature string, publicKey string) bool {
	messageBytes := []byte(message)
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false
	}
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return false
	}
	var result bool
	if c.dilithiumMode == 2 {
		if len(publicKey) != 1344 {
			return false
		}
		var publicKey eddilithium2.PublicKey
		publicKey.Unpack((*[1344]byte)(publicKeyBytes))
		result = eddilithium2.Verify(&publicKey, messageBytes, signatureBytes)
	} else {
		if len(publicKeyBytes) != 2009 {
			return false
		}
		var publicKey eddilithium3.PublicKey
		publicKey.Unpack((*[2009]byte)(publicKeyBytes))
		result = eddilithium3.Verify(&publicKey, messageBytes, signatureBytes)
	}
	return result
}

func (c *Client) Close() {
	close(c.tokenRotationQuitCh)
}

type ClientOptions struct {
	ProjectKey string
	Provider   string
	Name       string
	ApiKey     string
	RoleKey    string
}

func NewClient(options ClientOptions) (*Client, error) {
	authenticatePayload := struct {
		ProviderType string `json:"providerType,omitempty"`
		ProjectKey   string `json:"projectKey,omitempty"`
		RoleKey      string `json:"roleKey,omitempty"`
		Name         string `json:"name,omitempty"`
		Token        string `json:"token,omitempty"`
		Type         string `json:"type,omitempty"`
		ApiKey       string `json:"apiKey,omitempty"`
	}{Type: "sdk"}

	if options.ProjectKey != "" {
		authenticatePayload.ProjectKey = options.ProjectKey
	} else {
		authenticatePayload.ProjectKey = os.Getenv("MAGELLANIC_PROJECT_KEY")
		if authenticatePayload.ProjectKey == "" {
			return nil, errors.New("project key missing")
		}
	}
	if options.ApiKey != "" {
		authenticatePayload.ApiKey = options.ApiKey
	} else {
		authenticatePayload.ApiKey = os.Getenv("MAGELLANIC_API_KEY")
	}
	if options.Provider != "" {
		authenticatePayload.ProviderType = options.Provider
	} else {
		authenticatePayload.ProviderType = os.Getenv("MAGELLANIC_PROVIDER_TYPE")
		if authenticatePayload.ProviderType == "" {
			// TODO: detect provider properly
			if authenticatePayload.ApiKey == "" {
				authenticatePayload.ProviderType = "k8s"
			}
		}
	}
	if options.Name != "" {
		authenticatePayload.Name = options.Name
	} else {
		authenticatePayload.Name = os.Getenv("MAGELLANIC_WORKLOAD_NAME")
	}
	if options.RoleKey != "" {
		authenticatePayload.RoleKey = options.RoleKey
	} else {
		authenticatePayload.RoleKey = os.Getenv("MAGELLANIC_ROLE_KEY")
	}

	if authenticatePayload.ProviderType == "k8s" {
		tokenBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
		if err != nil {
			return nil, err
		}
		authenticatePayload.Token = string(tokenBytes)
	}

	apiUrl := os.Getenv("MAGELLANIC_API_URL")
	if apiUrl == "" {
		apiUrl = "https://api.magellanic.ai"
	}
	baseUrl := apiUrl + "/public-api/workloads"
	reqClient := req.NewClient().SetBaseURL(baseUrl)

	var authResponse struct {
		Mode                int    `json:"mode"`
		Id                  string `json:"id"`
		Token               string `json:"token"`
		TokenExpiryDate     string `json:"tokenExpiryDate"`
		PublicKey           string `json:"publicKey"`
		DilithiumPrivateKey string `json:"dilithiumPrivateKey"`
	}

	_, err := reqClient.R().
		SetBody(&authenticatePayload).
		SetSuccessResult(&authResponse).
		Post("/auth")
	if err != nil {
		return nil, err
	}
	reqClient.SetCommonHeader(ID_HEADER_NAME, authResponse.Id)

	client := &Client{
		reqClient:           reqClient,
		Id:                  authResponse.Id,
		token:               authResponse.Token,
		tokenRotationQuitCh: make(chan bool, 1),
		//tokenPublicKey:      authResponse.PublicKey,
		dilithiumMode: authResponse.Mode,
		ErrorCh:       make(chan Error),
	}

	client.dilithiumPrivateKey, err = base64.StdEncoding.DecodeString(authResponse.DilithiumPrivateKey)
	if err != nil {
		return nil, err
	}

	client.startTokenRotation(authResponse.TokenExpiryDate)

	return client, nil
}
