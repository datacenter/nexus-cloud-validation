// Package nxos is a a Cisco NXOS NX-API REST client library for Go.
package nxos

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"time"
	"workspace/models"

	log "github.com/sirupsen/logrus"
)

const DefaultMaxRetries int = 3
const DefaultBackoffMinDelay int = 4
const DefaultBackoffMaxDelay int = 60
const DefaultBackoffDelayFactor float64 = 3

// ClientUrl stores URL specific parameters
type ClientUrl struct {
	// Url is the NXOS device IP or hostname, e.g. https://10.0.0.1:443 (port is optional).
	Url string
	// LastRefresh is the timestamp of the last token refresh interval.
	LastRefresh time.Time
	// Token is the current authentication token
	Token string
}

// Client is an HTTP NXOS NX-API client.
// Use nxos.NewClient to initiate a client.
// This will ensure proper cookie handling and processing of modifiers.
type Client struct {
	// HttpClient is the *http.Client used for API requests.
	HttpClient *http.Client
	// Protocol is either http or https
	Protocol string
	// Port is the port NXAPI is running on
	Port int
	// Endpoint is the NXOS hostname or IP
	Endpoint string
	// Usr is the NXOS device username.
	Usr string
	// Pwd is the NXOS device password.
	Pwd string
	// Insecure determines if insecure https connections are allowed.
	Insecure bool
	// Maximum number of retries
	MaxRetries int
	// Minimum delay between two retries
	BackoffMinDelay int
	// Maximum delay between two retries
	BackoffMaxDelay int
	// Backoff delay factor
	BackoffDelayFactor float64
}

// NewClient creates a new NXOS HTTP client.
// Pass modifiers in to modify the behavior of the client, e.g.
//
//	client, _ := NewClient("apic", "user", "password", true, RequestTimeout(120))
func NewClient(endpoint string, usr string, pwd string, insecure bool, use_http bool, port int, mods ...func(*Client)) (Client, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
	}

	cookieJar, _ := cookiejar.New(nil)
	httpClient := http.Client{
		Timeout:   60 * time.Second,
		Transport: tr,
		Jar:       cookieJar,
	}
	protocol := "https"
	if use_http {
		protocol = "http"
	}
	if port == 0 {
		if protocol == "http" {
			port = 80
		} else {
			port = 443
		}
	}
	client := Client{
		HttpClient:         &httpClient,
		Protocol:           protocol,
		Port:               port,
		Endpoint:           endpoint,
		Usr:                usr,
		Pwd:                pwd,
		Insecure:           insecure,
		MaxRetries:         DefaultMaxRetries,
		BackoffMinDelay:    DefaultBackoffMinDelay,
		BackoffMaxDelay:    DefaultBackoffMaxDelay,
		BackoffDelayFactor: DefaultBackoffDelayFactor,
	}

	for _, mod := range mods {
		mod(&client)
	}
	return client, nil
}

// RequestTimeout modifies the HTTP request timeout from the default of 60 seconds.
func RequestTimeout(x time.Duration) func(*Client) {
	return func(client *Client) {
		client.HttpClient.Timeout = x * time.Second
	}
}

// MaxRetries modifies the maximum number of retries from the default of 3.
func MaxRetries(x int) func(*Client) {
	return func(client *Client) {
		client.MaxRetries = x
	}
}

// BackoffMinDelay modifies the minimum delay between two retries from the default of 4.
func BackoffMinDelay(x int) func(*Client) {
	return func(client *Client) {
		client.BackoffMinDelay = x
	}
}

// BackoffMaxDelay modifies the maximum delay between two retries from the default of 60.
func BackoffMaxDelay(x int) func(*Client) {
	return func(client *Client) {
		client.BackoffMaxDelay = x
	}
}

// BackoffDelayFactor modifies the backoff delay factor from the default of 3.
func BackoffDelayFactor(x float64) func(*Client) {
	return func(client *Client) {
		client.BackoffDelayFactor = x
	}
}

// CreateJSONRequest - helper function for creating json based http requests
func (c *Client) CreateJSONRequest(method string, path string, params interface{}) (*http.Request, error) {
	var request *http.Request
	var buf bytes.Buffer
	url := fmt.Sprintf("%s://%s:%d%s", c.Protocol, c.Endpoint, c.Port, path)
	err := json.NewEncoder(&buf).Encode(&params)
	if err != nil {
		return request, err
	}
	request, err = http.NewRequest(method, url, &buf)
	if err != nil {
		return request, err
	}
	if params == nil {
		request.Body = http.NoBody
	}
	request.Header.Set("Content-Type", "application/json")
	return request, nil
}

// Call - function for handling http requests
func (c *Client) Call(request *http.Request, result interface{}, want_array bool) error {
	var response *http.Response
	for attempts := 0; ; attempts++ {
		r, err := c.HttpClient.Do(request)
		if err != nil {
			if ok := c.Backoff(attempts); !ok {
				log.Errorf("HTTP Connection error occurred: %+v", err)
				log.Debugf("Exit from Do method")
				return err
			} else {
				log.Errorf("HTTP Connection failed: %s, retries: %v", err, attempts)
				continue
			}
		}
		defer r.Body.Close()
		response = r
		break
	}
	if !(response.StatusCode >= 200 && response.StatusCode <= 299) {
		var rawBodyBuffer bytes.Buffer
		// Decode raw response, usually contains
		// additional error details
		body := io.TeeReader(response.Body, &rawBodyBuffer)
		var responseBody interface{}
		json.NewDecoder(body).Decode(&responseBody)
		return fmt.Errorf("request %+v\n failed with status code %d\n response %+v\n%+v", request,
			response.StatusCode, responseBody,
			response)
	}
	// If no result is expected, don't attempt to decode a potentially
	// empty response stream and avoid incurring EOF errors
	if result == nil {
		return nil
	}
	var base_result models.NxosBaseResponse
	err := json.NewDecoder(response.Body).Decode(&base_result)
	if err != nil {
		return err
	}
	err = json.Unmarshal(base_result.Bytes(want_array), &result)
	if err != nil {
		log.Error(err)
	}
	return err
}

// Login authenticates to the NXOS device.
func (client *Client) Login() error {
	var payload models.NxosLoginPayload
	payload.CreateLogin(client.Usr, client.Pwd)
	req, err := client.CreateJSONRequest(http.MethodPost, "/api/aaaLogin.json", payload)
	if err != nil {
		log.Error(err)
		return err
	}
	var res models.NxosLoginResponse
	err = client.Call(req, res, false)
	if err != nil {
		log.Error(err)
		return err
	}
	return nil
}

func (client *Client) GetDn(dn string, result interface{}, want_array bool) error {
	req, err := client.CreateJSONRequest(http.MethodGet, fmt.Sprintf("/api/mo/%s", dn), nil)
	if err != nil {
		return err
	}
	err = client.Call(req, &result, want_array)
	return err
}

func (client *Client) GetClass(dn string, result interface{}, want_array bool) error {
	req, err := client.CreateJSONRequest(http.MethodGet, fmt.Sprintf("/api/class/%s", dn), nil)
	if err != nil {
		return err
	}
	err = client.Call(req, &result, want_array)
	return err
}

// Backoff waits following an exponential backoff algorithm
func (client *Client) Backoff(attempts int) bool {
	log.Printf("[DEBUG] Begining backoff method: attempts %v on %v", attempts, client.MaxRetries)
	if attempts >= client.MaxRetries {
		log.Printf("[DEBUG] Exit from backoff method with return value false")
		return false
	}

	minDelay := time.Duration(client.BackoffMinDelay) * time.Second
	maxDelay := time.Duration(client.BackoffMaxDelay) * time.Second

	min := float64(minDelay)
	backoff := min * math.Pow(client.BackoffDelayFactor, float64(attempts))
	if backoff > float64(maxDelay) {
		backoff = float64(maxDelay)
	}
	backoff = (rand.Float64()/2+0.5)*(backoff-min) + min
	backoffDuration := time.Duration(backoff)
	log.Printf("[TRACE] Starting sleeping for %v", backoffDuration.Round(time.Second))
	time.Sleep(backoffDuration)
	log.Printf("[DEBUG] Exit from backoff method with return value true")
	return true
}

func (client *Client) GetCliShow(cmd string) (models.CliShowResult, error) {
	var result models.CliShowResult
	url := fmt.Sprintf("%s://%s:%d/ins", client.Protocol, client.Endpoint, client.Port)

	payload := models.CliShowPaylaod{
		InsApi: struct {
			Version      string "json:\"version\""
			Type         string "json:\"type\""
			Chunk        string "json:\"chunk\""
			Sid          string "json:\"sid\""
			Input        string "json:\"input\""
			OutputFormat string "json:\"output_format\""
		}{
			Version:      "1.0",
			Type:         "cli_show",
			Chunk:        "0",
			Sid:          "sid",
			Input:        cmd,
			OutputFormat: "json",
		},
	}
	var request *http.Request
	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(&payload)
	if err != nil {
		return result, err
	}
	request, err = http.NewRequest(http.MethodPost, url, &buf)
	if err != nil {
		return result, err
	}
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("Cache-Control", "no-cache")
	request.SetBasicAuth(client.Usr, client.Pwd)

	response, err := client.HttpClient.Do(request)
	if err != nil {
		return result, err
	}
	defer response.Body.Close()
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return result, err
	}
	return result, nil
}

func (client *Client) SendCliConf(cmd string) (models.CliConfResult, error) {
	var result models.CliConfResult
	url := fmt.Sprintf("%s://%s:%d/ins", client.Protocol, client.Endpoint, client.Port)

	payload := models.CliConfPayload{
		InsApi: struct {
			Version      string "json:\"version\""
			Type         string "json:\"type\""
			Chunk        string "json:\"chunk\""
			Sid          string "json:\"sid\""
			Input        string "json:\"input\""
			OutputFormat string "json:\"output_format\""
			Rollback     string "json:\"rollback\""
		}{
			Version:      "1.0",
			Type:         "cli_conf",
			Chunk:        "0",
			Sid:          "sid",
			Input:        cmd,
			OutputFormat: "json",
			Rollback:     "stop-on-error",
		},
	}
	var request *http.Request
	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(&payload)
	if err != nil {
		return result, err
	}
	request, err = http.NewRequest(http.MethodPost, url, &buf)
	if err != nil {
		return result, err
	}
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("Cache-Control", "no-cache")
	request.SetBasicAuth(client.Usr, client.Pwd)

	response, err := client.HttpClient.Do(request)
	if err != nil {
		return result, err
	}
	defer response.Body.Close()
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return result, err
	}
	return result, nil
}
