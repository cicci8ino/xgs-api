package rawdata

type LinkData struct {
	PortStatus []string      `json:"portstatus"`
	Speed      []string      `json:"speed"`
	PVIDs      []int         `json:"pvids"`
	VLANStatus []([2]string) `json:"vlanstatus"`
	Stats      []([3]int)    `json:"stats"`
}
