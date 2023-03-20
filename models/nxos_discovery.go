package models

type FeatureLldp struct {
	FeatureLldp struct {
		Attributes struct {
			AdminSt string `json:"adminSt"`
			Dn      string `json:"dn"`
		}
	} `json:"fmLldp"`
}

type CdpInstance struct {
	CdpInstance struct {
		Attributes struct {
			AdminSt string `json:"adminSt"`
			Dn      string `json:"dn"`
		}
	} `json:"cdpInst"`
}
