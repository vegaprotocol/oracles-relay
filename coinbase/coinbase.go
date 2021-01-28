package coinbase

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"time"

	"code.vegaprotocol.io/oracles-relay/openoracle"
)

const (
	baseURL = "https://api.pro.coinbase.com"
	// This publicly available, safe to keep in sources
	cbPubKey = "0xfCEAdAFab14d46e20144F48824d0C09B1a03F2BC"
)

// Config the configuration used to connect
// with the coinbase API
type Config struct {
	// used to authentify with the coinbase API
	KeyID      string `toml:"key_id"`
	Passphrase string `toml:"passphrase"`
	Secret     string `toml:"secret"`
	// how often do we call the coinbase oracle API
	Frequency time.Duration `toml:"frequency"`
}

type Worker struct {
	cfg Config
}

// New instantiate a new coinbase worker
func New(cfg Config) *Worker {
	return &Worker{
		cfg: cfg,
	}
}

// Pull will call the coinbase oracle API
// and return the last updates available
func (p *Worker) Pull() ([]byte, error) {
	t, err := p.getTime()
	if err != nil {
		return nil, err
	}

	btes, err := p.getOracleData(t)
	if err != nil {
		return nil, err
	}

	_, err = openoracle.UnmarshalVerify(btes, cbPubKey)
	if err != nil {
		return nil, err
	}

	return btes, nil
}

// getOracleData calls the coinbase API and return
// the raw data from the /oracle endpoint
func (p *Worker) getOracleData(t int64) ([]byte, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", urlJoin(baseURL, "oracle"), nil)
	if err != nil {
		return nil, err
	}

	// auth headers
	req.Header.Add("CB-ACCESS-KEY", p.cfg.KeyID)
	req.Header.Add("CB-ACCESS-PASSPHRASE", p.cfg.Passphrase)
	req.Header.Add("CB-ACCESS-TIMESTAMP", fmt.Sprintf("%v", t))
	req.Header.Add("CB-ACCESS-SIGN", sign(t, "GET", "/oracle", "", p.cfg.Secret))
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

// getTime is calling the time endpoint from the
// coinbase API, each request to coinbase require
// to set a timestamp being in a range of 30 seconds
// around the current timestamp from their API
// using this give us close to no chance to be wrong
func (p *Worker) getTime() (int64, error) {
	resp, err := http.Get(urlJoin(baseURL, "time"))
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}

	out := struct {
		Epoch float64 `json:"epoch"`
	}{}

	err = json.Unmarshal(body, &out)
	if err != nil {
		return 0, err
	}

	return int64(out.Epoch), nil
}

func urlJoin(baseURL string, segments ...string) string {
	u, err := url.Parse(baseURL)
	if err != nil {
		panic(err)
	}
	u.Path = path.Join(append([]string{u.Path}, segments...)...)
	return u.String()
}

// sign creae an hmac signature using the coinbase credentials
// in order to authentify our request.
func sign(timestamp int64, method, path, body, secret string) string {
	what := fmt.Sprintf("%v%v%v%v", timestamp, method, path, body)
	key, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		panic(err)
	}

	signature := hmac.New(sha256.New, key)
	_, err = signature.Write([]byte(what))
	if err != nil {
		panic(err)
	}

	return base64.StdEncoding.EncodeToString(signature.Sum(nil))
}
