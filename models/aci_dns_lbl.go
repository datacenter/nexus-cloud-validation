package models

type CtxOobDnsQuery struct {
	TotalCount string `json:"totalCount"`
	Imdata     []DnsLbl
}

type DnsLbl struct {
	DnsLbl struct {
		Attributes struct {
			Dn   string
			Name string
		}
	} `json:"dnsLbl"`
}

type DnsProviderQuery struct {
	TotalCount string `json:"totalCount"`
	Imdata     []DnsProv
}

type DnsProv struct {
	DnsProv struct {
		Attributes struct {
			Addr      string
			Dn        string
			Preferred string
		}
	} `json:"dnsProv"`
}

type DnsDomainQuery struct {
	TotalCount string `json:"totalCount"`
	Imdata     []DnsDomain
}

type DnsDomain struct {
	DnsDomain struct {
		Attributes struct {
			Name      string
			Dn        string
			IsDefault string `json:"isDefault"`
		}
	} `json:"dnsDomain"`
}
