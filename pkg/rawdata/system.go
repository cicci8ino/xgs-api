package rawdata

type SystemData struct {
	MaxPort        int    `json:"max_port"`
	ModelName      string `json:"model_name"`
	SysDevName     string `json:"sys_dev_name"`
	SysFMWName     string `json:"sys_fmw_ver"`
	SysBLDDate     string `json:"sys_bld_date"`
	SysMAC         string `json:"sys_MAC"`
	SysIP          string `json:"sys_IP"`
	SysSubnetMask  string `json:"sys_sbnt_mask"`
	SysGateway     string `json:"sys_gateway"`
	SysDHCPState   string `json:"sys_dhcp_state"`
	SysUptime      int    `json:"sys_uptime"`
	SysEEEState    string `json:"sys_eee_state"`
	SysLEDEcoMode  string `json:"sys_led_eco_mode"`
	SysHTTPState   int    `json:"sys_http_state"`
	SysHTTPsState  int    `json:"sys_https_state"`
	SysSessTimeout int    `json:"sys_sess_timeout"`
	SysMgmtVLAN    int    `json:"sys_mgmt_vlan"`
}
