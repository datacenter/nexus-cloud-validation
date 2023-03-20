package models

const PassMessage = "PASS"
const FailMessage = "Needs Attention"

type AciReturnResult struct {
	Type    string
	Results ApicResults
}

type ApicResults struct {
	DeviceConnector             VersionCheck
	FabricName                  string
	Endpoint                    string
	NexusInsightsCloudConnector VersionCheck
	ApicVision                  VersionCheck
	Nodes                       []NodeResult
	NodeResult                  BaseResult
	DNS                         DnsResult
	NTP                         BaseResult
	Proxy                       BaseResult
	Telemetry                   BaseResult
	OverallResult               BaseResult
}

type BaseResult struct {
	Result string
	Reason string
}

type VersionCheck struct {
	Result  string
	Reason  string
	Version string
}

type NodeResult struct {
	NodeId         string
	Result         string
	Reason         string
	Model          string
	Role           string
	Version        string
	OobMgmtAddress string
	NtpServers     []string
}

type DnsResult struct {
	Result    string
	Reason    string
	Providers []DnsProvider
	Domains   []DnsDomainResult
}

type DnsProvider struct {
	Address   string
	Preferred bool
}

type DnsDomainResult struct {
	Name    string
	Default bool
}

type NxosReturnResult struct {
	Type    string
	Results NxosResults
}

type NxosResults struct {
	OverallResult BaseResult
	Devices       []NxosDeviceResult
}

type NxosDeviceResult struct {
	Name              string
	Version           ValueResult
	MgmtIp            string
	Model             ValueResult
	Modular           bool
	Serial            string
	Linecards         []NxosLinecard
	LinecardResult    BaseResult
	Dns               DnsResult
	Ntp               NxosNtpResult
	Telemetry         BaseResult
	DiscoveryProtocol BaseResult
	PingTest          BaseResult
	Result            string
	Reason            string
}

func (device *NxosDeviceResult) AddReason(reason string) {
	if device.Reason != "" {
		device.Reason += " "
	}
	device.Reason += reason
}

type NxosLinecard struct {
	Model   string
	Slot    string
	Version string
}

type NxosNtpResult struct {
	Providers []string
	Result    string
	Reason    string
}

type ValueResult struct {
	Value  string
	Result string
	Reason string
}
