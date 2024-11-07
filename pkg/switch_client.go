package xgsapi

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"

	"github.com/cicci8ino/xgs-api/pkg/rawdata"
	"github.com/cicci8ino/xgs-api/pkg/utils"

	"github.com/rs/zerolog/log"
)

type SwitchClient struct {
	BaseURL    string
	Password   string
	Cookie     string
	ModelName  string
	XSRFToken  string
	AuthID     string
	HTTPClient *http.Client
	SystemData *rawdata.SystemData
}

func (s *SwitchClient) Init() {
	// TODO: specify CA or use system certificates
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	jar, _ := cookiejar.New(nil)
	s.HTTPClient = &http.Client{
		Jar:       jar,
		Transport: transport,
	}
	requestURL := utils.GetURL(s.BaseURL, utils.CGIGETPath, utils.LoginInfoCMD)

	var loginInfoDataResp rawdata.LoginInfoResp
	s.StoreParsedData(requestURL, &loginInfoDataResp)
	parsedURL, err := url.Parse(s.BaseURL)
	if err != nil {
		log.Fatal().Err(err).Msg("invalid URL")
	}
	if parsedURL.Scheme == "http" {
		modulus := loginInfoDataResp.Data.Modulus[:len(loginInfoDataResp.Data.Modulus)-1]
		log.Debug().Msg(modulus)
		publicKey, err := utils.CreatePublicKey(modulus, utils.HEXExponent)
		if err != nil {
			log.Fatal().Msg("can't set public key")
		}
		s.Password, err = utils.EncryptPassword(publicKey, s.Password)
		if err != nil {
			log.Fatal().Err(err).Msg("cannot encrypt password")
		}
	}
	s.XSRFToken, err = utils.GenXSRFToken()
	if err != nil {
		log.Fatal().Err(err).Msg("cannot generate xsrftoken")
	}
}

func (s *SwitchClient) Login() {
	passwordParams := url.Values{}
	passwordParams.Add("password", s.Password)
	requestURL := utils.GetURL(s.BaseURL, utils.CGISETPath, utils.LoginAuthCMD)
	bodyString := fmt.Sprintf(`{"%s&%s&xsrfToken=%s&%s":{}}`, "_ds=1", passwordParams.Encode(), s.XSRFToken, "_de=1")
	log.Debug().Msg(bodyString)
	jsonData := []byte(bodyString)
	req, err := http.NewRequest("POST", requestURL, bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	if err != nil {
		log.Fatal().Err(err).Msg("error creating request data")
	}
	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		log.Fatal().Err(err).Msg("posting login request")
	}
	bodyResponse, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != 200 {
		log.Fatal().Err(err).Msg("error reading response")
		return
	}
	var authResponse rawdata.AuthResponse
	err = json.Unmarshal(bodyResponse, &authResponse)
	if err != nil {
		log.Fatal().Err(err)
	}
	s.AuthID = authResponse.AuthID
}

func (s *SwitchClient) GetSessionCookie() {
	requestURL := utils.GetURL(s.BaseURL, utils.CGISETPath, utils.LoginStatusCMD)
	bodyString := fmt.Sprintf(`{"_ds=1&authId=%s&_de=1":{}}`, s.AuthID)
	jsonData := []byte(bodyString)
	req, err := http.NewRequest("POST", requestURL, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatal().Err(err).Msg("cannot post request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.HTTPClient.Do(req)
	for _, c := range resp.Cookies() {
		log.Debug().Msgf("%s=%s", c.Name, c.Value)
	}
}

func (s *SwitchClient) RawGet(requestURL string) ([]byte, error) {
	resp, err := s.HTTPClient.Get(requestURL)
	if (err) != nil {
		log.Fatal().Err(err).Msg("error fetching data")
	}
	body, err := io.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		log.Fatal().Err(err).Msg("error reading body")
	}
	return body, nil
}

func (s *SwitchClient) RawPost(requestURL string, v any) ([]byte, error) {
	jsonData, err := json.Marshal(v)
	if err != nil {
		log.Fatal().Err(err).Msg("cannot marshal data")
	}
	req, err := http.NewRequest("POST", requestURL, bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.HTTPClient.Do(req)
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal().Err(err)
	}
	return bodyBytes, nil
}

func (s *SwitchClient) StoreParsedData(url string, v any) error {
	body, _ := s.RawGet(url)
	var result map[string]interface{}
	err := json.Unmarshal(body, &result)

	if err != nil {
		log.Fatal().Err(err).Msg("error parsing xsrfToken")
	}
	xsrftoken, ok := result["xsrfToken"].(string)
	if ok {
		s.XSRFToken = xsrftoken
	}
	err = json.Unmarshal(body, v)
	if err != nil {
		log.Fatal().Err(err).Msg("error parsing data")
	}
	log.Debug().Interface("raw_data", v).Msg("raw_data")
	return nil

}

func (s *SwitchClient) AddVLAN(vlan rawdata.VLAN) {
	s.FetchVLANData()
	requestURL := utils.GetURL(s.BaseURL, utils.CGISETPath, utils.VLANAddModCMD)
	bodyString := fmt.Sprintf(`{"%s&%s&xsrfToken=%s&%s":{}}`, "_ds=1", vlan.String(), s.XSRFToken, "_de=1")
	jsonData := []byte(bodyString)
	log.Debug().Msg(string(bodyString))
	req, err := http.NewRequest("POST", requestURL, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatal().Err(err).Msg("cannot create request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		log.Fatal().Err(err).Msg("posting login request")
	}
	if resp.StatusCode != 200 {
		log.Warn().Msg("cannot create VLAN")
	}

}

func (s *SwitchClient) FetchSystemData() rawdata.SystemDataResp {
	url := utils.GetURL(s.BaseURL, utils.CGIGETPath, utils.SystemDataCMD)
	var systemDataResp rawdata.SystemDataResp
	s.StoreParsedData(url, &systemDataResp)
	s.SystemData = &systemDataResp.Data
	url = utils.GetURL(s.BaseURL, utils.CGIGETPath, utils.SysMGMTDataCMD)
	s.StoreParsedData(url, &systemDataResp)
	return systemDataResp
}

func (s *SwitchClient) FetchLinkData() rawdata.LinkDataResp {
	url := utils.GetURL(s.BaseURL, utils.CGIGETPath, utils.LinkDataCMD)
	var linkDataResp rawdata.LinkDataResp
	s.StoreParsedData(url, &linkDataResp)
	return linkDataResp
}

func (s *SwitchClient) FetchVLANData() rawdata.VLANDataResp {
	url := utils.GetURL(s.BaseURL, utils.CGIGETPath, utils.VLANListCMD)
	var vlanDataResp rawdata.VLANDataResp
	s.StoreParsedData(url, &vlanDataResp)

	return vlanDataResp
}
