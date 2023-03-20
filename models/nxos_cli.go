package models

type CliShowResult struct {
	InsApi struct {
		Type    string        `json:"type"`
		Version string        `json:"version"`
		Sid     string        `json:"sid"`
		Outputs CliShowOutput `json:"Outputs"`
	} `json:"ins_api"`
}

type CliShowOutput struct {
	Output struct {
		Input string `json:"input"`
		Msg   string `json:"msg"`
		Code  string `json:"code"`
		Body  struct {
			NfFilter struct {
				Configure struct {
					Terminal interface{} `json:"m:terminal,omitempty"`
				} `json:"m:configure"`
			} `json:"nf:filter"`
		} `json:"body"`
	} `json:"output"`
}

type CliShowIntersightResult struct {
	Intersight struct {
		UseVrf struct {
			Param struct {
				Value string `json:"__XML__value"`
			} `json:"__XML__PARAM__vrf-cfg-name"`
		} `json:"use-vrf"`
		Proxy struct {
			ProxyServer struct {
				Value string `json:"__XML__value"`
			} `json:"__XML__PARAM__proxy-server"`
		} `json:"proxy"`
	} `json:"intersight"`
}

type CliShowPaylaod struct {
	InsApi struct {
		Version      string `json:"version"`
		Type         string `json:"type"`
		Chunk        string `json:"chunk"`
		Sid          string `json:"sid"`
		Input        string `json:"input"`
		OutputFormat string `json:"output_format"`
	} `json:"ins_api"`
}

type CliConfPayload struct {
	InsApi struct {
		Version      string `json:"version"`
		Type         string `json:"type"`
		Chunk        string `json:"chunk"`
		Sid          string `json:"sid"`
		Input        string `json:"input"`
		OutputFormat string `json:"output_format"`
		Rollback     string `json:"rollback"`
	} `json:"ins_api"`
}

type CliConfResult struct {
	InsApi struct {
		Type    string        `json:"type"`
		Version string        `json:"version"`
		Sid     string        `json:"sid"`
		Outputs CliConfOutput `json:"Outputs"`
	} `json:"ins_api"`
}

type CliConfOutput struct {
	Output struct {
		Input string `json:"input"`
		Msg   string `json:"msg"`
		Code  string `json:"code"`
		Body  string `json:"body"`
	} `json:"output"`
}
