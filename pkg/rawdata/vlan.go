package rawdata

type VLANData struct {
	PVIDs  []int         `json:"pvids"`
	QVLANs []interface{} `json:"qvlans"`
}

type VLANDataResp struct {
	Data VLANData `json:"data"`
}
