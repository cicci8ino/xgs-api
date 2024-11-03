package data

type Port struct {
	Type      interface{}
	IsCopper  bool
	PortSpeed int
	IsUP      bool
	PVID      int
	TXCounter int
	RXCounter int
	CRCErrors int
}
