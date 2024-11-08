package rawdata

import "fmt"

type VLANData struct {
	PVIDs  []int         `json:"pvids"`
	QVLANs []interface{} `json:"qvlans"`
}

type VLAN struct {
	PVID   int
	Lplist string
	Tpbmp  string
}

func (v *VLAN) String() string {
	return fmt.Sprintf("vid=%d&lplist=%s&tpbmp=%s", v.PVID, v.Lplist, v.Tpbmp)
}
