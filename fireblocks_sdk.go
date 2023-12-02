package fireblocks

import (
	"bytes"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"time"

	"github.com/gojek/heimdall/v7/hystrix"
	"github.com/golang-jwt/jwt"
	log "github.com/sirupsen/logrus"
)

type FbKeyMgmt struct {
	privateKey *rsa.PrivateKey
	apiKey     string
	rnd        *rand.Rand
}

func NewInstanceKeyMgmt(pk *rsa.PrivateKey, apiKey string) *FbKeyMgmt {
	var s secrets
	k := new(FbKeyMgmt)
	k.privateKey = pk
	k.apiKey = apiKey
	k.rnd = rand.New(s)
	return k
}

func ReadPrivateKey(path string) ([]byte, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return data, nil
}

const timeout = 5 * time.Millisecond

type secrets struct{}

func (s secrets) Seed(seed int64) {}

func (s secrets) Uint64() (r uint64) {
	err := binary.Read(crand.Reader, binary.BigEndian, &r)
	if err != nil {
		log.Error(err)
	}
	return r
}

func (s secrets) Int63() int64 {
	return int64(s.Uint64() & ^uint64(1<<63))
}

func (k *FbKeyMgmt) createAndSignJWTToken(path string, bodyJSON string) (string, error) {

	token := &jwt.MapClaims{
		"uri":      path,
		"nonce":    k.rnd.Int63(),
		"iat":      time.Now().Unix(),
		"exp":      time.Now().Add(time.Second * 55).Unix(),
		"sub":      k.apiKey,
		"bodyHash": createHash(bodyJSON),
	}

	j := jwt.NewWithClaims(jwt.SigningMethodRS256, token)
	signedToken, err := j.SignedString(k.privateKey)
	if err != nil {
		log.Error(err)
	}

	return signedToken, err
}

func createHash(data string) string {
	h := sha256.New()
	h.Write([]byte(data))
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed)
}

type SDK struct {
	httpClient *hystrix.Client
	apiBaseURL string
	kto        *FbKeyMgmt
}

// NewInstance - create new type to handle Fireblocks API requests
func NewInstance(pk []byte, ak string, url string, t time.Duration) *SDK {

	if t == time.Duration(0) {
		// use default
		t = timeout
	}

	s := new(SDK)
	s.apiBaseURL = url
	privateK, err := jwt.ParseRSAPrivateKeyFromPEM(pk)
	if err != nil {
		log.Error(err)
	}

	s.kto = NewInstanceKeyMgmt(privateK, ak)
	s.httpClient = newCircuitBreakerHttpClient(t)
	return s
}

func newCircuitBreakerHttpClient(t time.Duration) *hystrix.Client {

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
		InsecureSkipVerify: false,
	}
	c := hystrix.NewClient(hystrix.WithHTTPTimeout(t),
		hystrix.WithFallbackFunc(func(err error) error {
			log.Errorf("no fallback func implemented: %s", err)
			return err
		}))
	return c
}

// getRequest - internal method to handle API call to Fireblocks
func (s *SDK) getRequest(path string) (string, error) {

	urlEndPoint := s.apiBaseURL + path
	token, err := s.kto.createAndSignJWTToken(path, "")
	if err != nil {
		log.Error(err)
		return fmt.Sprintf("{message: \"%s.\"}", "error signing JWT token"), err
	}

	request, err := http.NewRequest(http.MethodGet, urlEndPoint, nil)
	if err != nil {
		log.Error(err)
		return fmt.Sprintf("{message: \"%s.\"}", "error creating NewRequest"), err
	}

	request.Header.Add("X-API-Key", s.kto.apiKey)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %v", token))

	response, err := s.httpClient.Do(request)
	if err != nil {
		log.Error(err)
		return "", err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Error(err)
		}
	}(response.Body)

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Errorf("error communicating with fireblocks: %v", err)
		return "", err
	}

	if response.StatusCode >= 300 {
		errMsg := fmt.Sprintf("fireblocks server: %s \n %s", response.Status, string(data))
		log.Warning(errMsg)
	}

	return string(data), err
}

func (s *SDK) changeRequest(path string, payload []byte, idempotencyKey string, requestType string) (string, error) {

	urlEndPoint := s.apiBaseURL + path
	token, err := s.kto.createAndSignJWTToken(path, string(payload))
	if err != nil {
		log.Error(err)
		return fmt.Sprintf("{message: \"%s.\"}", "error signing JWT token"), err
	}

	request, err := http.NewRequest(requestType, urlEndPoint, bytes.NewBuffer(payload))
	if err != nil {
		log.Error(err)
		return fmt.Sprintf("{message: \"%s.\"}", "error creating NewRequest"), err
	}
	request.Header.Add("X-API-Key", string(s.kto.apiKey))
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %v", token))
	request.Header.Add("Content-Type", "application/json")

	if len(idempotencyKey) > 0 {
		request.Header.Add("Idempotency-Key", idempotencyKey)
	}
	response, err := s.httpClient.Do(request)
	if err != nil {
		log.Error(err)
		return "", err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Error(err)
		}
	}(response.Body)

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Errorf("error on communicating with Fireblocks: %v  \n data: %s", err, data)
		return "", err
	}

	if response.StatusCode >= 300 {
		errMsg := fmt.Sprintf("fireblocks server: %s \n %s", response.Status, string(data))
		log.Warning(errMsg)
	}

	return string(data), err

}

func (s *SDK) Passthrough(method Method, path string, payload []byte) (interface{}, error) {

	_method := "GET"
	if method == "POST" {
		_method = "POST"
	} else if method == "PUT" {
		_method = "PUT"
	} else if method == "DELETE" {
		_method = "DELETE"
	}
	if _method == "GET" {
		return s.getRequest(path)
	}
	return s.changeRequest(path, payload, "", _method)
}
