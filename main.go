package main

import (
	"os"

	xgsapi "github.com/cicci8ino/xgs-api/pkg"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	log.Logger = zerolog.New(os.Stderr).With().
		Timestamp().
		Caller().
		Logger()
	baseURL := os.Getenv("ZYXEL_HOSTNAME")
	password := os.Getenv("ZYXEL_PASSWORD")
	zyxelSwitch := xgsapi.SwitchClient{
		BaseURL:  baseURL,
		Password: password,
	}
	zyxelSwitch.Init()
	zyxelSwitch.Login()
	zyxelSwitch.FetchSystemData()
	zyxelSwitch.FetchLinkData()
	zyxelSwitch.FetchVLANData()
	/*vlan := rawdata.VLAN{
		PVID:   245,
		Lplist: "0xfff",
		Tpbmp:  "0xfff",
	}
	zyxelSwitch.AddVLAN(vlan)*/
}
