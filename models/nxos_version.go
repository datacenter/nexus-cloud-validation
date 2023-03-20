package models

type NxosShowVersion struct {
	SysmgrShowVersion struct {
		Attributes struct {
			BiosVersion   string `json:"biosVersion"`
			BootflashSize string `json:"bootflashSize"`
			NxosImageFile string `json:"nxosImageFile"`
			NxosVersion   string `json:"nxosVersion"`
		} `json:"attributes"`
	} `json:"sysmgrShowVersion"`
}

type NxosAggregateSystemTable struct {
	AggregateSystemTable struct {
		Attributes struct {
			Dn                     string `json:"dn"`
			IsControllerConfigured string `json:"isControllerConfigured"`
			MgmtIp                 string `json:"mgmtIp"`
			SwitchType             string `json:"switchType"`
		} `json:"attributes"`
	} `json:"aggregateSystemTable"`
}

type NxosEquipmentChassis struct {
	EquipmentChassis struct {
		Attributes struct {
			Description string `json:"descr"`
			Dn          string `json:"dn"`
			Model       string `json:"model"`
			Serial      string `json:"ser"`
		} `json:"attributes"`
	} `json:"eqptCh"`
}

type NxosTopSystem struct {
	TopSystem struct {
		Attributes struct {
			Dn     string `json:"dn"`
			Name   string `json:"name"`
			Serial string `json:"serial"`
		} `json:"attributes"`
	} `json:"topSystem"`
}
