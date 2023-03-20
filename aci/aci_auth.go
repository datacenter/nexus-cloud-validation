package aci

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

type Auth struct {
	Token         string
	Expiry        time.Time
	apicCreatedAt time.Time
	realCreatedAt time.Time
	offset        int64
}

func (au *Auth) IsValid() bool {
	if au.Token != "" && au.Expiry.Unix() > au.estimateExpireTime() {
		return true
	}
	return false
}

func (t *Auth) CalculateExpiry(willExpire int64) {
	t.Expiry = time.Unix((t.apicCreatedAt.Unix() + willExpire), 0)
}
func (t *Auth) CaclulateOffset() {
	t.offset = t.apicCreatedAt.Unix() - t.realCreatedAt.Unix()
}

func (t *Auth) estimateExpireTime() int64 {
	return time.Now().Unix() + t.offset
}

func (client *Client) InjectAuthenticationHeader(req *http.Request, path string) (*http.Request, error) {
	log.Debug("Begin Injection")
	client.l.Lock()
	defer client.l.Unlock()
	if client.password != "" {
		if client.AuthToken == nil || !client.AuthToken.IsValid() {
			err := client.Authenticate()
			if err != nil {
				return nil, err
			}
		}
		req.AddCookie(&http.Cookie{
			Name:  "APIC-Cookie",
			Value: client.AuthToken.Token,
		})
		return req, nil
	} else if client.privatekey != "" && client.adminCert != "" {
		if client.appUserName != "" {
			if client.AuthToken != nil && client.AuthToken.IsValid() {
				req.AddCookie(&http.Cookie{
					Name:  "APIC-Cookie",
					Value: client.AuthToken.Token,
				})
				return req, nil
			}
		}

		var bodyStr string
		if req.Method != "GET" {
			buffer, _ := ioutil.ReadAll(req.Body)
			rdr2 := ioutil.NopCloser(bytes.NewBuffer(buffer))

			req.Body = rdr2
			bodyStr = string(buffer)
		}
		contentStr := ""
		if bodyStr != "{}" {
			contentStr = fmt.Sprintf("%s%s%s", req.Method, path, bodyStr)
		} else {
			contentStr = fmt.Sprintf("%s%s", req.Method, path)

		}
		log.Debugf("Content %s", contentStr)
		content := []byte(contentStr)

		signature, err := createSignature(content, client.privatekey)
		log.Debugf("Signature %s", signature)
		if err != nil {
			return req, err
		}
		req.AddCookie(&http.Cookie{
			Name:  "APIC-Request-Signature",
			Value: signature,
		})
		req.AddCookie(&http.Cookie{
			Name:  "APIC-Certificate-Algorithm",
			Value: "v1.0",
		})

		// Actual certificate fingerprint/thumbprint generation is not required
		// Simply setting cookie to fingerprint is sufficient for cert-based requests.
		req.AddCookie(&http.Cookie{
			Name:  "APIC-Certificate-Fingerprint",
			Value: "fingerprint",
		})
		if client.appUserName != "" {
			req.AddCookie(&http.Cookie{
				Name:  "APIC-Certificate-DN",
				Value: fmt.Sprintf("uni/userext/appuser-%s/usercert-%s", client.appUserName, client.adminCert),
			})
		} else {
			req.AddCookie(&http.Cookie{
				Name:  "APIC-Certificate-DN",
				Value: fmt.Sprintf("uni/userext/user-%s/usercert-%s", client.username, client.adminCert),
			})
		}
		log.Debug("finished signature creation")
		return req, nil
	} else {

		return req, fmt.Errorf("Anyone of password or privatekey/certificate name is must.")
	}

	return req, nil
}

func createSignature(content []byte, keypath string) (string, error) {
	log.Debug("Begin Create signature")
	hasher := sha256.New()
	hasher.Write(content)
	log.Debugf("begin Read private key inside createsignature")

	privkey, err := loadPrivateKey(keypath)
	log.Debug("finish read private key inside Create signature")

	if err != nil {
		return "", err
	}
	log.Debug("begin signing signature")

	signedData, err := rsa.SignPKCS1v15(nil, privkey, crypto.SHA256, hasher.Sum(nil))
	log.Debug("finish signing signature")

	if err != nil {
		return "", err
	}
	log.Debug("begin final encoding signature")

	signature := base64.StdEncoding.EncodeToString(signedData)
	log.Debug("finish final signature")

	return signature, nil
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	log.Debug("begin load private key inside loadPrivateKey")
	var data []byte
	var err error

	// os.Stat may panic for certain RSA Keys due to character combinations in the
	// key string.  To work around this, perform basic checks if the path is the
	// key itself
	if strings.HasPrefix(path, "-----BEGIN RSA PRIVATE KEY-----") || strings.Contains(path, "\n") {
		data = []byte(path)
	} else {
		isFile := fileExists(path)
		if isFile {
			data, err = ioutil.ReadFile(path)
		} else {
			data = []byte(path)
		}
	}

	log.Debug("private key read finish inside loadPrivateKey")

	if err != nil {
		return nil, err
	}
	log.Debug("finish load private key inside loadPrivateKey")

	return parsePrivateKey(data)
}

func parsePrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	log.Debug("Begin parse private key inside parsePrivateKey")

	block, _ := pem.Decode(pemBytes)
	log.Debug("pem decode finish parse private key inside parsePrivateKey")

	if block == nil {
		return nil, errors.New("ssh: no key found")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		privkey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		log.Debug("x509 parsing  private key inside parsePrivateKey")

		if err != nil {
			return nil, err
		}
		return privkey, err
	case "PRIVATE KEY":
		parsedresult, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		log.Debug("x509 parsing private key inside parsePrivateKey")

		if err != nil {
			return nil, err
		}
		privkey := parsedresult.(*rsa.PrivateKey)
		log.Debug("finish private parse private key inside parsePrivateKey")

		return privkey, nil
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
