package models

type FabricPodQuery struct {
	TotalCount string `json:"totalCount"`
	Imdata     []FabricPod
}

type FabricPod struct {
	FabricPod struct {
		Attributes struct {
			Dn      string
			Id      string
			PodType string `json:"podType"`
		}
	} `json:"fabricPod"`
}

type FabricPodProfileQuery struct {
	TotalCount string `json:"totalCount"`
	Imdata     []FabricPodP
}

type FabricPodP struct {
	FabricPodP struct {
		Attributes struct {
			Dn   string
			Name string
		}
		Children []PconsNodeDeployCtx `json:"children,omitempty"`
	} `json:"fabricPodP"`
}

type PconsNodeDeployCtx struct {
	PconsNodeDeployCtx struct {
		Attributes struct {
			DeployStatus string `json:"deployStatus"`
			NodeId       string `json:"nodeId"`
		}
		Children []PconsResourceCtx
	} `json:"pconsNodeDeployCtx"`
}

type PconsResourceCtx struct {
	PconsResourceCtx struct {
		Attributes struct {
			CtxClass string `json:"ctxClass"`
			CtxDn    string `json:"ctxDn"`
		}
	} `json:"pconsResourceCtx"`
}

type FabricPodSelectorQuery struct {
	TotalCount string `json:"totalCount"`
	Imdata     []FabricPodS
}

type FabricPodS struct {
	FabricPodS struct {
		Attributes struct {
			Dn   string
			Name string
			Type string
		}
		Children []FabricRsPodPolicyGroup
	} `json:"fabricPodS"`
}

type FabricRsPodPolicyGroup struct {
	FabricRsPodPGrp struct {
		Attributes struct {
			Dn  string `json:"dn,omitempty"`
			TDn string `json:"tDn,omitempty"`
		}
	} `json:"fabricRsPodPGrp"`
}

type FabricTimePolicyQuery struct {
	TotalCount string `json:"totalCount"`
	Imdata     []FabricRsTimePol
}

type FabricRsTimePol struct {
	FabricRsTimePol struct {
		Attributes struct {
			Dn  string `json:"dn,omitempty"`
			TDn string `json:"tDn,omitempty"`
		}
	} `json:"fabricRsTimePol"`
}

type NtpTimeProvidersQuery struct {
	TotalCount string `json:"totalCount"`
	Imdata     []DatetimeNtpProv
}

type DatetimeNtpProv struct {
	DatetimeNtpProv struct {
		Attributes struct {
			Dn        string `json:"dn,omitempty"`
			Name      string `json:"name,omitempty"`
			Preferred string
		}
	} `json:"datetimeNtpProv"`
}
