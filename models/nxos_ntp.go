package models

type NxosNtpProvider struct {
	DatetimeNtpProvider struct {
		Attributes struct {
			Dn        string `json:"attributes"`
			Name      string `json:"name"`
			Preferred string `json:"preferred"`
			ProvT     string `json:"provT"`
			Vrf       string `json:"vrf"`
		} `json:"attributes"`
		Children []NxosNtpProviderStatus `json:"children"`
	} `json:"datetimeNtpProvider"`
}

type NxosNtpProviderStatus struct {
	DatetimeNtpProviderStatus struct {
		Attributes struct {
			Delay      string `json:"delay"`
			DelayRaw   string `json:"delayRaw"`
			Dispersion string `json:"dispersion"`
			Flags      string `json:"flags"`
			HostPoll   string `json:"hostPoll"`
			PeerPoll   string `json:"peerPoll"`
			Stratum    string `json:"stratum"`
		} `json:"attributes"`
	} `json:"datetimeNtpProviderStatus"`
}
