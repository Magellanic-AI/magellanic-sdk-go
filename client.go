package magellanic

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/cloudflare/circl/sign/dilithium"
	"github.com/cloudflare/circl/sign/eddilithium2"
	"github.com/cloudflare/circl/sign/eddilithium3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/imroc/req/v3"
	kyberk2so "github.com/symbolicsoft/kyber-k2so"
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
	tokenPublicKey      *rsa.PublicKey

	dilithiumMode       int
	dilithiumPrivateKey string

	ErrorCh chan Error
}

func NewClient(options ClientOptions) (client *Client, err error) {
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

	_, err = reqClient.R().
		SetBody(&authenticatePayload).
		SetSuccessResult(&authResponse).
		Post("/auth")
	if err != nil {
		return nil, err
	}
	reqClient.SetCommonHeader(ID_HEADER_NAME, authResponse.Id)

	spki, _ := pem.Decode([]byte(authResponse.PublicKey))
	if spki == nil {
		return nil, errors.New("couldn't decode public key")
	}
	parsedKey, err := x509.ParsePKIXPublicKey(spki.Bytes)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse public key: %s", err.Error())
	}

	client = &Client{
		reqClient:           reqClient,
		Id:                  authResponse.Id,
		token:               authResponse.Token,
		tokenRotationQuitCh: make(chan bool, 1),
		tokenPublicKey:      parsedKey.(*rsa.PublicKey),
		dilithiumMode:       authResponse.Mode,
		dilithiumPrivateKey: authResponse.DilithiumPrivateKey,
		ErrorCh:             make(chan Error),
	}

	client.startTokenRotation(authResponse.TokenExpiryDate)
	return
}

func (c *Client) GetMyToken() (token string) {
	c.tokenLock.RLock()
	defer c.tokenLock.RUnlock()
	return c.token
}

type claims struct {
	WorkloadId string                     `json:"workloadId"`
	Role       string                     `json:"role,omitempty"`
	Resources  map[string]map[string]bool `json:"resources,omitempty"`
	jwt.RegisteredClaims
}

func (c *Client) GenerateHeaders() (headers [2][2]string) {
	return [2][2]string{{AUTH_HEADER_NAME, c.GetMyToken()}, {ID_HEADER_NAME, c.Id}}
}

func (c *Client) ValidateToken(workloadId string, token string) (verifyResult bool) {
	_, err := c.getTokenClaims(workloadId, token)
	return err == nil
}

func (c *Client) ValidateTokenWithAccess(workloadId string, token string, resource string, action string) (verifyResult bool) {
	claims, err := c.getTokenClaims(workloadId, token)
	if err != nil {
		return false
	}
	if res, ok := claims.Resources[resource]; ok {
		if act, ok := res[action]; ok {
			return act
		}
	}
	return false
}

func (c *Client) getTokenClaims(token string, workloadId string) (*claims, error) {
	parsed, err := jwt.ParseWithClaims(token, &claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return c.tokenPublicKey, nil
	})

	if err != nil {
		return nil, err
	}
	if claims, ok := parsed.Claims.(*claims); ok && parsed.Valid && claims.WorkloadId == workloadId {
		return claims, nil
	} else {
		return nil, errors.New("invalid token")
	}
}

func (c *Client) GetConfig(configId string, result interface{}) (err error) {
	var getConfigPayload struct {
		authPayload
		ConfigId string `json:"configId"`
	}
	getConfigPayload.authPayload = c.createAuthPayload()
	getConfigPayload.ConfigId = configId
	_, err = c.reqClient.R().
		SetBody(&getConfigPayload).
		SetSuccessResult(&result).
		Post("/config")
	return err
}

func (c *Client) DilithiumGenerateKeys(mode int) (publicKey string, privateKey string, err error) {
	var (
		_publicKey  dilithium.PublicKey
		_privateKey dilithium.PrivateKey
	)
	if mode == 2 {
		_publicKey, _privateKey, err = eddilithium2.GenerateKey(rand.Reader)
		if err != nil {
			return "", "", err
		}
	} else if mode == 3 {
		_publicKey, _privateKey, err = eddilithium3.GenerateKey(rand.Reader)
		if err != nil {
			return "", "", err
		}
	} else {
		return "", "", errors.New("invalid mode, please provide either 2 or 3")
	}
	return base64.StdEncoding.EncodeToString(_publicKey.Bytes()), base64.StdEncoding.EncodeToString(_privateKey.Bytes()), nil
}

func (c *Client) DilithiumSign(mode int, privateKey, message string) (signature string, err error) {
	messageB := []byte(message)
	privateKeyB, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return "", nil
	}
	if mode == 2 {
		if len(privateKeyB) != 2560 {
			return "", errors.New("invalid key length")
		}
		var signature [eddilithium2.SignatureSize]byte
		var privateKey eddilithium2.PrivateKey
		privateKey.Unpack((*[2560]byte)(privateKeyB))
		eddilithium2.SignTo(&privateKey, messageB, signature[:])
		return base64.StdEncoding.EncodeToString(signature[:]), nil
	} else if mode == 3 {
		if len(privateKeyB) != 4057 {
			return "", errors.New("invalid key length")
		}
		var signature [eddilithium3.SignatureSize]byte
		var privateKey eddilithium3.PrivateKey
		privateKey.Unpack((*[4057]byte)(privateKeyB))
		eddilithium3.SignTo(&privateKey, messageB, signature[:])
		return base64.StdEncoding.EncodeToString(signature[:]), nil
	} else {
		return "", errors.New("invalid mode, please provide either 2 or 3")
	}
}

func (c *Client) DilithiumVerify(mode int, publicKey, message, signature string) (verifyResult bool, err error) {
	messageBytes := []byte(message)
	signatureB, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}
	publicKeyB, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return false, err
	}
	var result bool
	if mode == 2 {
		if len(publicKeyB) != 1344 {
			return false, errors.New("invalid key length")
		}
		var publicKey eddilithium2.PublicKey
		publicKey.Unpack((*[1344]byte)(publicKeyB))
		result = eddilithium2.Verify(&publicKey, messageBytes, signatureB)
	} else if mode == 3 {
		if len(publicKeyB) != 2009 {
			return false, errors.New("invalid key length")
		}
		var publicKey eddilithium3.PublicKey
		publicKey.Unpack((*[2009]byte)(publicKeyB))
		result = eddilithium3.Verify(&publicKey, messageBytes, signatureB)
	} else {
		return false, errors.New("invalid mode, please provide either 2 or 3")
	}
	return result, nil
}

func (c *Client) KyberGenerateKeys() (publicKey string, privateKey string, err error) {
	privateKeyB, publicKeyB, err := kyberk2so.KemKeypair768()
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(publicKeyB[:]), base64.StdEncoding.EncodeToString(privateKeyB[:]), nil
}

func (c *Client) KyberEncrypt(publicKey string) (ciphertext string, secret string, err error) {
	publicKeyB, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return "", "", err
	}
	if len(publicKeyB) != 1184 {
		return "", "", errors.New("invalid key length")
	}
	ciphertextB, secretB, err := kyberk2so.KemEncrypt768([1184]byte(publicKeyB))
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertextB[:]), base64.StdEncoding.EncodeToString(secretB[:]), nil
}

func (c *Client) KyberDecrypt(privateKey string, ciphertext string) (secret string, err error) {
	privateKeyB, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return "", err
	}
	if len(privateKeyB) != 2400 {
		return "", errors.New("invalid key length")
	}
	ciphertextB, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	if len(ciphertextB) != 1088 {
		return "", errors.New("invalid ciphertext length")
	}
	secretB, err := kyberk2so.KemDecrypt768([1088]byte(ciphertextB), [2400]byte(privateKeyB))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(secretB[:]), err
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
	for {
		select {
		case <-c.tokenRotationQuitCh:
			return
		case <-timer.C:
			rotateTokenPayload := c.createAuthPayload()
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

type authPayload struct {
	Token     string `json:"token"`
	Signature string `json:"signature"`
}

func (c *Client) createAuthPayload() authPayload {
	var authPayload authPayload
	authPayload.Token = c.GetMyToken()
	authPayload.Signature, _ = c.DilithiumSign(c.dilithiumMode, c.dilithiumPrivateKey, authPayload.Token)
	return authPayload
}
