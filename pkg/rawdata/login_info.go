package rawdata

type LoginInfo struct {
	SysFirstLogin string `json:"sys_first_login"`
	ModelName     string `json:"model_name"`
	Logined       string `json:"logined"`
	Modulus       string `json:"modulus"`
}

type LoginInfoResp struct {
	Data LoginInfo `json:"data"`
}
