package models

type NxosDnsDomain struct {
	DnsDom struct {
		Attributes struct {
			Dn   string `json:"dn"`
			Name string `json:"name"`
		} `json:"attributes"`
	} `json:"dnsDom"`
}

type NxosDnsProvider struct {
	DnsProvider struct {
		Attributes struct {
			Addr string `json:"addr"`
			Dn   string `json:"dn"`
			Name string `json:"name"`
		} `json:"attributes"`
	} `json:"dnsProvider"`
}
