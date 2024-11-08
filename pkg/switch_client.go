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
	XSRFToken  string
	HTTPClient *http.Client
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

	var loginInfoDataResp rawdata.LoginInfo
	s.StoreParsedData(requestURL, &loginInfoDataResp)
	parsedURL, err := url.Parse(s.BaseURL)
	if err != nil {
		log.Fatal().Err(err).Msg("invalid URL")
	}
	if parsedURL.Scheme == "http" {
		modulus := loginInfoDataResp.Modulus[:len(loginInfoDataResp.Modulus)-1]
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
	bodyBytes, err := s.Post(requestURL, passwordParams.Encode())
	if err != nil {
		log.Fatal().Err(err).Msg("login post failed")
	}

	var authResponse rawdata.AuthResponse
	err = json.Unmarshal(bodyBytes, &authResponse)
	if err != nil {
		log.Fatal().Err(err).Msg("problem umarshaling login data")
	}
	s.GetSessionCookie(authResponse.AuthID)
}

func (s *SwitchClient) GetSessionCookie(authID string) {
	requestURL := utils.GetURL(s.BaseURL, utils.CGISETPath, utils.LoginStatusCMD)
	bodyString := fmt.Sprintf(`{"_ds=1&authId=%s&_de=1":{}}`, authID)
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

func (s *SwitchClient) Get(requestURL string) ([]byte, error) {
	resp, err := s.HTTPClient.Get(requestURL)
	if (err) != nil {
		log.Fatal().Err(err).Msg("error fetching data")
	}
	body, err := io.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		log.Fatal().Err(err).Msg("error reading body")
	}
	if resp.StatusCode != 200 {
		log.Error().Msg("get request returned non 200 response code")
		return nil, fmt.Errorf("resp code %d", resp.StatusCode)
	}
	return body, nil
}

func (s *SwitchClient) Post(requestURL string, bodyData string) ([]byte, error) {
	bodyString := fmt.Sprintf(`{"%s&%s&xsrfToken=%s&%s":{}}`, "_ds=1", bodyData, s.XSRFToken, "_de=1")
	jsonData := []byte(bodyString)
	log.Debug().Msg(string(bodyString))
	req, err := http.NewRequest("POST", requestURL, bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.HTTPClient.Do(req)
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal().Err(err).Interface("bodyData", bodyString).Msg("error posting data")
	}
	if resp.StatusCode != 200 {
		log.Error().Msg("post request returned non 200 response code")
		return nil, fmt.Errorf("resp code %d", resp.StatusCode)
	}
	return bodyBytes, nil
}

func (s *SwitchClient) StoreParsedData(url string, v any) error {
	body, _ := s.Get(url)
	var result map[string]interface{}
	err := json.Unmarshal(body, &result)

	if err != nil {
		log.Fatal().Err(err).Msg("error parsing xsrfToken")
	}
	xsrftoken, ok := result["xsrfToken"].(string)
	if ok {
		// storing xsrftoken, to be used for subsequent post call
		s.XSRFToken = xsrftoken
	}
	err = json.Unmarshal(body, v)
	if err != nil {
		log.Fatal().Err(err).Msg("error parsing data")
	}
	data, ok := result["data"].(any)
	marshaledData, _ := json.Marshal(data)
	if err != nil {
		log.Fatal().Err(err).Msg("error marshaling data field")
	}
	err = json.Unmarshal(marshaledData, v)
	log.Debug().Interface("raw_data", v).Msg("raw_data")
	return nil

}

func (s *SwitchClient) AddVLAN(vlan rawdata.VLAN) {
	requestURL := utils.GetURL(s.BaseURL, utils.CGISETPath, utils.VLANAddModCMD)
	s.Post(requestURL, vlan.String())
}

func (s *SwitchClient) FetchSystemData() rawdata.SystemData {
	// system data is provided by two endpoints
	// systemdatacmd and sysmgmtdata
	// might be worth to use two seperate call and two different data structure
	url := utils.GetURL(s.BaseURL, utils.CGIGETPath, utils.SystemDataCMD)
	var systemData rawdata.SystemData
	s.StoreParsedData(url, &systemData)
	url = utils.GetURL(s.BaseURL, utils.CGIGETPath, utils.SysMGMTDataCMD)
	s.StoreParsedData(url, &systemData)
	return systemData
}

func (s *SwitchClient) FetchLinkData() rawdata.LinkData {
	url := utils.GetURL(s.BaseURL, utils.CGIGETPath, utils.LinkDataCMD)
	var linkDataResp rawdata.LinkData
	s.StoreParsedData(url, &linkDataResp)
	return linkDataResp
}

func (s *SwitchClient) FetchVLANData() rawdata.VLANData {
	url := utils.GetURL(s.BaseURL, utils.CGIGETPath, utils.VLANListCMD)
	var vlanDataResp rawdata.VLANData
	s.StoreParsedData(url, &vlanDataResp)

	return vlanDataResp
}
