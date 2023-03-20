package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"workspace/aci"
	"workspace/configuration"
	"workspace/formatting"
	"workspace/models"
	"workspace/nxos"

	// "github.com/ciscoecosystem/aci-go-client/v2/client"
	// "github.com/ciscoecosystem/aci-go-client/v2/models"
	"github.com/xuri/excelize/v2"
	"golang.org/x/term"

	"gopkg.in/yaml.v3"

	log "github.com/sirupsen/logrus"
)

type excel_formatting struct {
	styles map[string]int
}

func toCharStr(i int) string {
	return string('A' - 1 + i)
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

// Reads yaml configuration file
func readConf(filename string) (*models.Config, error) {
	buf, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	c := &models.Config{}
	err = yaml.Unmarshal(buf, c)
	if err != nil {
		return nil, fmt.Errorf("in file %q: %w", filename, err)
	}

	return c, err
}

// Creates excel styles used for report
func createExcelStyles(f *excelize.File, e *excel_formatting) error {
	heading, err := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{
			Bold: true,
			Size: 18,
		},
	})
	if err != nil {
		return err
	}
	overall_result_heading, err := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{
			Bold:  true,
			Size:  18,
			Color: "FFFFFF",
		},
		Fill: excelize.Fill{
			Color:   []string{"5B9CD5"},
			Type:    "pattern",
			Pattern: 1,
		},
	})
	if err != nil {
		return err
	}
	overall_result_pass, err := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{
			Size:  16,
			Color: "305496",
		},
		Fill: excelize.Fill{
			Color:   []string{"A9D08E"},
			Type:    "pattern",
			Pattern: 1,
		},
	})
	if err != nil {
		return err
	}
	overall_result_fail, err := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{
			Size:  16,
			Color: "305496",
		},
		Fill: excelize.Fill{
			Color:   []string{"FFC000"},
			Type:    "pattern",
			Pattern: 1,
		},
	})
	if err != nil {
		return err
	}
	title, err := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{
			Bold:  true,
			Size:  22,
			Color: "FFFFFF",
		},
		Fill: excelize.Fill{
			Color:   []string{"5B9CD5"},
			Type:    "pattern",
			Pattern: 1,
		},
	})
	if err != nil {
		return err
	}
	table, err := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{
			Size:  14,
			Color: "FFFFFF",
		},
	})
	if err != nil {
		return err
	}

	table_columns, err := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{
			Size: 14,
		},
		Border: []excelize.Border{
			{
				Type:  "right",
				Color: "5B9CD5",
				Style: 1,
			},
		},
	})
	if err != nil {
		return err
	}

	table_header, err := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{
			Size:  14,
			Color: "FFFFFF",
			Bold:  true,
		},
		Fill: excelize.Fill{
			Color:   []string{"5B9CD5"},
			Type:    "pattern",
			Pattern: 1,
		},
	})
	if err != nil {
		return err
	}

	table_header_white_top, err := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{
			Size:  14,
			Color: "FFFFFF",
			Bold:  true,
		},
		Fill: excelize.Fill{
			Color:   []string{"5B9CD5"},
			Type:    "pattern",
			Pattern: 1,
		},
		Border: []excelize.Border{
			{
				Type:  "top",
				Color: "FFFFFF",
				Style: 1,
			},
		},
	})
	if err != nil {
		return err
	}

	table_cell, err := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{
			Size: 14,
		},
		Border: []excelize.Border{
			{
				Type:  "right",
				Color: "5B9CD5",
				Style: 1,
			},
			{
				Type:  "left",
				Color: "5B9CD5",
				Style: 1,
			},
			{
				Type:  "top",
				Color: "5B9CD5",
				Style: 1,
			},
			{
				Type:  "bottom",
				Color: "5B9CD5",
				Style: 1,
			},
		},
	})
	if err != nil {
		return err
	}

	pass, err := f.NewStyle(&excelize.Style{
		Fill: excelize.Fill{
			Color:   []string{"A9D08E"},
			Type:    "pattern",
			Pattern: 1,
		},
		Font: &excelize.Font{
			Bold:  true,
			Size:  14,
			Color: "305496",
		},
	})
	if err != nil {
		return err
	}

	fail, err := f.NewStyle(&excelize.Style{
		Fill: excelize.Fill{
			Color:   []string{"FFC000"},
			Type:    "pattern",
			Pattern: 1,
		},
		Font: &excelize.Font{
			Bold:  true,
			Size:  16,
			Color: "305496",
		},
	})
	if err != nil {
		return err
	}
	cell_pass, err := f.NewStyle(&excelize.Style{
		Fill: excelize.Fill{
			Color:   []string{"A9D08E"},
			Type:    "pattern",
			Pattern: 1,
		},
		Font: &excelize.Font{
			Size:  14,
			Color: "305496",
		},
		Border: []excelize.Border{
			{
				Type:  "right",
				Color: "5B9CD5",
				Style: 1,
			},
			{
				Type:  "left",
				Color: "5B9CD5",
				Style: 1,
			},
			{
				Type:  "top",
				Color: "5B9CD5",
				Style: 1,
			},
			{
				Type:  "bottom",
				Color: "5B9CD5",
				Style: 1,
			},
		},
	})
	if err != nil {
		return err
	}

	cell_fail, err := f.NewStyle(&excelize.Style{
		Fill: excelize.Fill{
			Color:   []string{"FFC000"},
			Type:    "pattern",
			Pattern: 1,
		},
		Font: &excelize.Font{
			Size:  14,
			Color: "305496",
		},
		Border: []excelize.Border{
			{
				Type:  "right",
				Color: "5B9CD5",
				Style: 1,
			},
			{
				Type:  "left",
				Color: "5B9CD5",
				Style: 1,
			},
			{
				Type:  "top",
				Color: "5B9CD5",
				Style: 1,
			},
			{
				Type:  "bottom",
				Color: "5B9CD5",
				Style: 1,
			},
		},
	})
	if err != nil {
		return err
	}
	border_left, err := f.NewStyle(&excelize.Style{
		Border: []excelize.Border{
			{
				Type:  "left",
				Color: "5B9CD5",
				Style: 1,
			},
		},
	})
	if err != nil {
		return err
	}
	border_right, err := f.NewStyle(&excelize.Style{
		Border: []excelize.Border{
			{
				Type:  "right",
				Color: "5B9CD5",
				Style: 1,
			},
		},
	})
	if err != nil {
		return err
	}
	border_bottom, err := f.NewStyle(&excelize.Style{
		Border: []excelize.Border{
			{
				Type:  "bottom",
				Color: "5B9CD5",
				Style: 1,
			},
		},
	})
	if err != nil {
		return err
	}
	border_bottom_left, err := f.NewStyle(&excelize.Style{
		Border: []excelize.Border{
			{
				Type:  "left",
				Color: "5B9CD5",
				Style: 1,
			},
			{
				Type:  "bottom",
				Color: "5B9CD5",
				Style: 1,
			},
		},
	})
	if err != nil {
		return err
	}
	border_bottom_right, err := f.NewStyle(&excelize.Style{
		Border: []excelize.Border{
			{
				Type:  "right",
				Color: "5B9CD5",
				Style: 1,
			},
			{
				Type:  "bottom",
				Color: "5B9CD5",
				Style: 1,
			},
		},
	})
	if err != nil {
		return err
	}
	e.styles["heading"] = heading
	e.styles["overall_result_heading"] = overall_result_heading
	e.styles["overall_result_pass"] = overall_result_pass
	e.styles["overall_result_fail"] = overall_result_fail
	e.styles["table"] = table
	e.styles["table_header"] = table_header
	e.styles["table_header_white_top"] = table_header_white_top
	e.styles["table_columns"] = table_columns
	e.styles["title"] = title
	e.styles["pass"] = pass
	e.styles["fail"] = fail
	e.styles["table_cell"] = table_cell
	e.styles["cell_pass"] = cell_pass
	e.styles["cell_fail"] = cell_fail
	e.styles["border_left"] = border_left
	e.styles["border_right"] = border_right
	e.styles["border_bottom"] = border_bottom
	e.styles["border_bottom_left"] = border_bottom_left
	e.styles["border_bottom_right"] = border_bottom_right
	return nil
}

// Connects to ACI fabric and performs onboarding checks. The returned struct contains all of the results
func handleAci(config *models.Config, pass string, matrix *configuration.Matrix) (*models.ApicResults, error) {
	var results models.ApicResults
	results.Endpoint = config.Aci.Endpoint
	//* Initiate ACI client
	client := aci.GetClient(fmt.Sprintf("https://%s", config.Aci.Endpoint), config.Aci.Username, aci.Password(pass), aci.Insecure(true))
	err := client.Authenticate()
	if err != nil {
		return &results, err
	}

	//* Get Pod Policies
	var pod_profile_query models.FabricPodProfileQuery
	cont, err := client.GetViaURL("api/node/mo/uni/fabric.json?query-target=subtree&target-subtree-class=fabricPodP")
	if err != nil {
		return &results, err
	}
	err = json.Unmarshal(cont.Bytes(), &pod_profile_query)
	if err != nil {
		return &results, err
	}

	var pod_policy_groups []string

	//* Iterate through pods to find Node policies
	pod_profile_node_mapping := make(map[string]string)
	for _, profile := range pod_profile_query.Imdata {
		//* Get Selectors
		var pod_selector_query models.FabricPodSelectorQuery
		cont, err := client.GetViaURL(fmt.Sprintf("api/node/mo/uni/fabric/podprof-%s.json?rsp-subtree=full&query-target=children", profile.FabricPodP.Attributes.Name))
		if err != nil {
			return &results, err
		}
		err = json.Unmarshal(cont.Bytes(), &pod_selector_query)
		if err != nil {
			return &results, err
		}
		//* Iterate through selectors for Node association
		for _, selector := range pod_selector_query.Imdata {
			//* skip selectors with no profile group associated
			if len(selector.FabricPodS.Children) == 0 {
				continue
			}
			var pod_profile_deployment_query models.FabricPodProfileQuery
			cont, err := client.GetViaURL(fmt.Sprintf("api/node/mo/%s.json?rsp-subtree-include=full-deployment", selector.FabricPodS.Attributes.Dn))
			if err != nil {
				return &results, err
			}
			err = json.Unmarshal(cont.Bytes(), &pod_profile_deployment_query)
			if err != nil {
				return &results, err
			}
			for _, p := range pod_profile_deployment_query.Imdata {
				for _, deployCtx := range p.FabricPodP.Children {
					if deployCtx.PconsNodeDeployCtx.Attributes.DeployStatus == "deployed" {
						pod_profile_node_mapping[deployCtx.PconsNodeDeployCtx.Children[0].PconsResourceCtx.Attributes.CtxDn] = selector.FabricPodS.Children[0].FabricRsPodPGrp.Attributes.TDn
						if len(pod_policy_groups) == 0 || !contains(pod_policy_groups, selector.FabricPodS.Children[0].FabricRsPodPGrp.Attributes.TDn) {
							pod_policy_groups = append(pod_policy_groups, selector.FabricPodS.Children[0].FabricRsPodPGrp.Attributes.TDn)
						}
					}
				}
			}
		}
	}

	//* Iterate through Pod Policy Groups and resolve policies
	ntp_server_map := make(map[string][]string)
	for _, group := range pod_policy_groups {
		//* Get time provider policy
		var time_provider_query models.FabricTimePolicyQuery
		cont, err := client.GetViaURL(fmt.Sprintf("api/node/mo/%s.json?query-target=children&target-subtree-class=fabricRsTimePol", group))
		if err != nil {
			return &results, err
		}
		err = json.Unmarshal(cont.Bytes(), &time_provider_query)
		if err != nil {
			return &results, err
		}
		//* Iterate NTP servers
		var ntp_server_list_query models.NtpTimeProvidersQuery
		cont, err = client.GetViaURL(fmt.Sprintf("api/node/mo/%s.json?query-target=subtree&target-subtree-class=datetimeNtpProv", time_provider_query.Imdata[0].FabricRsTimePol.Attributes.TDn))
		if err != nil {
			return &results, err
		}
		err = json.Unmarshal(cont.Bytes(), &ntp_server_list_query)
		if err != nil {
			return &results, err
		}
		var servers []string
		for _, server := range ntp_server_list_query.Imdata {
			if server.DatetimeNtpProv.Attributes.Preferred == "yes" {
				servers = append(servers, fmt.Sprintf("%s(P)", server.DatetimeNtpProv.Attributes.Name))
			} else {
				servers = append(servers, server.DatetimeNtpProv.Attributes.Name)
			}
		}
		ntp_server_map[group] = servers
	}

	//* Get Topology Systems
	cont, err = client.GetViaURL("api/class/topSystem.json")
	if err != nil {
		return &results, err
	}
	systems := models.SystemListFromContainer(cont)

	//* Get fabric nodes
	cont, err = client.GetViaURL("api/class/fabricNode.json")
	if err != nil {
		return &results, err
	}
	list := models.TopologyFabricNodeListFromContainer(cont)

	ntp_valid := true
	nodes_valid := true
	for _, node := range list {
		//* Check if firmware model and firmware are valid
		hw_valid := false
		fw_valid := false
		if node.Role == "leaf" || node.Role == "spine" {
			for _, model := range matrix.Aci.Switch.Models.Supported {
				if strings.Contains(strings.ToLower(node.Model), strings.ToLower(model)) {
					hw_valid = true
				}
			}
			fw_valid = formatting.InArray(strings.Split(node.Version, "-")[1], matrix.Aci.Switch.Versions)
		} else if node.Role == "controller" {
			hw_valid = true
			fw_valid = formatting.InArray(node.Version, matrix.Aci.Controller.Versions)
		}
		system := models.FindSystemByDn(systems, node.DistinguishedName)
		if results.FabricName == "" && node.Role == "controller" {
			results.FabricName = system.FabricDomain
		}
		if system == nil {
			log.Warnf("Unable to find system details for dn: %s", node.DistinguishedName)
		}
		oob_valid := system.OobMgmtAddr != "" || system.OobMgmtAddr6 != ""
		reason := ""
		if !hw_valid {
			reason = reason + "Model is not currently supported"
		}
		if !fw_valid {
			if reason != "" {
				reason += "; "
			}
			reason += "Firmware version not currently supported"
		}
		if !oob_valid {
			if reason != "" {
				reason += "; "
			}
			reason += "Out of band management is not configured on this node"
		}
		ntp_servers := ntp_server_map[pod_profile_node_mapping[node.DistinguishedName]]
		if len(ntp_servers) == 0 {
			if reason != "" {
				reason += "; "
			}
			reason += "NTP is not configured"
			ntp_valid = false
		}
		validity := models.PassMessage
		if reason != "" {
			validity = models.FailMessage
			nodes_valid = false
		}

		results.Nodes = append(results.Nodes, models.NodeResult{
			NodeId:         node.Id,
			Model:          node.Model,
			Role:           node.Role,
			Version:        node.Version,
			OobMgmtAddress: fmt.Sprintf("%s/%s", system.OobMgmtAddr, system.OobMgmtAddr6),
			NtpServers:     ntp_servers,
			Result:         validity,
			Reason:         reason,
		})
	}

	sort.Slice(results.Nodes, func(i, j int) bool {
		i_val, _ := strconv.Atoi(results.Nodes[i].NodeId)
		j_val, _ := strconv.Atoi(results.Nodes[j].NodeId)
		return i_val < j_val
	})

	if nodes_valid {
		results.NodeResult = models.BaseResult{
			Result: models.PassMessage,
			Reason: "",
		}
	} else {
		results.NodeResult = models.BaseResult{
			Result: models.FailMessage,
			Reason: "One or more nodes failed to meet onboarding requirements. See node table for details",
		}
	}
	if ntp_valid {
		results.NTP = models.BaseResult{
			Result: models.PassMessage,
			Reason: "",
		}
	} else {
		results.NTP = models.BaseResult{
			Result: models.FailMessage,
			Reason: "One or more nodes missing NTP configuration",
		}
	}

	//* Check device connector version
	req, err := client.MakeRestRequestRaw("GET", "connector/Versions", nil, true)
	if err != nil {
		return &results, err
	}
	var dc_versions []models.ConnectorVersion
	_, err = client.DoRaw(req, &dc_versions)
	if err != nil {
		return &results, err
	}
	if len(dc_versions) == 0 {
		results.DeviceConnector = models.VersionCheck{
			Result:  models.FailMessage,
			Version: "Unknown",
			Reason:  "Unable to detect device connector version.",
		}
	} else {
		valid, err := dc_versions[0].HasValidVersion(matrix.Aci.Device_Connector.Versions)
		if err != nil {
			log.Fatalf("error verifying Device Connector version: %s", err)
		}
		if !valid {
			results.DeviceConnector = models.VersionCheck{
				Result:  models.FailMessage,
				Version: dc_versions[0].Version,
				Reason:  fmt.Sprintf("Device Connector version is not supported: %s", dc_versions[0].Version),
			}
		} else {
			results.DeviceConnector = models.VersionCheck{
				Result:  models.PassMessage,
				Version: dc_versions[0].Version,
				Reason:  fmt.Sprintf("Found supported version: %s", dc_versions[0].Version),
			}
		}
	}

	//* Get Nexus Insights Cloud Connector version
	cont, err = client.GetViaURL("api/node/mo/pluginContr/plugin-Cisco_NIBASE.json?rsp-subtree-include=health,fault-count")
	if err != nil {
		return &results, err
	}
	var nicc_query models.ApPluginQuery
	err = json.Unmarshal(cont.Bytes(), &nicc_query)
	if err != nil {
		return &results, err
	}
	nicc := nicc_query.Imdata[0]
	nicc_fault_count, err := nicc.FaultCount()
	if err != nil {
		log.Warnf("error retrieving Nexus Insights Cloud Connector fault count: %s", err)
	}
	valid, err := nicc.HasValidVersion(matrix.Aci.Nexus_Cloud_Insights_Cloud_Connector.Versions)
	if err != nil {
		log.Fatalf("error verifying Nexus Insights Cloud Connector version: %s", err)
	}
	log.Infof("NICC Version Valid: %s(%v) OperState: %s PluginState: %s Faults: %d", nicc.ApPlugin.Attributes.Version, valid, nicc.ApPlugin.Attributes.OperState, nicc.ApPlugin.Attributes.PluginSt, nicc_fault_count)
	if !valid {
		results.NexusInsightsCloudConnector = models.VersionCheck{
			Result:  models.FailMessage,
			Version: nicc.ApPlugin.Attributes.Version,
			Reason:  fmt.Sprintf("Nexus Insights Cloud Connector version is not supported: %s", nicc.ApPlugin.Attributes.Version),
		}
	} else {
		results.NexusInsightsCloudConnector = models.VersionCheck{
			Result:  models.PassMessage,
			Version: nicc.ApPlugin.Attributes.Version,
			Reason:  fmt.Sprintf("Found supported version: %s", nicc.ApPlugin.Attributes.Version),
		}
	}

	//* Get APIC Vision version
	cont, err = client.GetViaURL("api/node/mo/pluginContr/plugin-Cisco_ApicVision.json?rsp-subtree-include=health,fault-count")
	if err != nil {
		log.Warn("An error occurred retrieving Apic Vision version: %s", err)
	}
	var apic_vision_query models.ApPluginQuery
	err = json.Unmarshal(cont.Bytes(), &apic_vision_query)
	if err != nil {
		return &results, err
	}
	apic_vision := apic_vision_query.Imdata[0]
	apic_vision_fault_count, err := apic_vision.FaultCount()
	if err != nil {
		log.Warnf("error retrieving Apic Vision fault count: %s", err)
	}
	valid, err = apic_vision.HasValidVersion(matrix.Aci.Apic_Vision_App.Versions)
	if err != nil {
		log.Fatalf("error verifying Apic Vision version: %s", err)
	}
	log.Infof("Apic Vision Version Valid: %s(%v) OperState: %s PluginState: %s Faults: %d", apic_vision.ApPlugin.Attributes.Version, valid, apic_vision.ApPlugin.Attributes.OperState, apic_vision.ApPlugin.Attributes.PluginSt, apic_vision_fault_count)
	if !valid {
		results.ApicVision = models.VersionCheck{
			Result:  models.FailMessage,
			Version: apic_vision.ApPlugin.Attributes.Version,
			Reason:  fmt.Sprintf("Apic Vision version is not supported: %s", nicc.ApPlugin.Attributes.Version),
		}
	} else {
		results.ApicVision = models.VersionCheck{
			Result:  models.PassMessage,
			Version: apic_vision.ApPlugin.Attributes.Version,
			Reason:  fmt.Sprintf("Found supported version: %s", apic_vision.ApPlugin.Attributes.Version),
		}
	}

	//* Get OOB ctx dns labels
	cont, err = client.GetViaURL("api/node/mo/uni/tn-mgmt/ctx-oob.json?query-target=subtree&target-subtree-class=dnsLbl")
	if err != nil {
		log.Warn("An error occurred retrieving Apic Vision version: %s", err)
	}
	var ctx_oob_dns_query models.CtxOobDnsQuery
	err = json.Unmarshal(cont.Bytes(), &ctx_oob_dns_query)
	if err != nil {
		return &results, err
	}
	//* Iterate through each label
	var dns_results models.DnsResult
	for _, label := range ctx_oob_dns_query.Imdata {
		cont, err = client.GetViaURL(fmt.Sprintf("api/node/mo/uni/fabric/dnsp-%s.json?query-target=subtree&target-subtree-class=dnsProv", label.DnsLbl.Attributes.Name))
		if err != nil {
			log.Warn("An error occurred retrieving dns label providers: %s", err)
			return &results, err
		}
		var dns_provider_query models.DnsProviderQuery
		err = json.Unmarshal(cont.Bytes(), &dns_provider_query)
		if err != nil {
			return &results, err
		}
		for _, provider := range dns_provider_query.Imdata {
			dns_results.Providers = append(dns_results.Providers, models.DnsProvider{
				Address:   provider.DnsProv.Attributes.Addr,
				Preferred: provider.DnsProv.Attributes.Preferred == "yes",
			})
		}
		cont, err = client.GetViaURL(fmt.Sprintf("api/node/mo/uni/fabric/dnsp-%s.json?query-target=subtree&target-subtree-class=dnsDomain", label.DnsLbl.Attributes.Name))
		if err != nil {
			log.Warn("An error occurred retrieving dns label domains: %s", err)
			return &results, err
		}
		var dns_domain_query models.DnsDomainQuery
		err = json.Unmarshal(cont.Bytes(), &dns_domain_query)
		if err != nil {
			return &results, err
		}
		for _, domain := range dns_domain_query.Imdata {
			dns_results.Domains = append(dns_results.Domains, models.DnsDomainResult{
				Name:    domain.DnsDomain.Attributes.Name,
				Default: domain.DnsDomain.Attributes.IsDefault == "yes",
			})
		}
	}
	dns_reason := ""
	if len(dns_results.Providers) == 0 {
		dns_reason += "No DNS providers found for oob vrf in mgmt tenant"
	}
	if len(dns_results.Domains) == 0 {
		if dns_reason != "" {
			dns_reason += "; "
		}
		dns_reason += "No DNS search domains found for oob vrf in mgmt tenant"
	}
	if dns_reason == "" {
		results.DNS = models.DnsResult{
			Result:    models.PassMessage,
			Reason:    dns_reason,
			Providers: dns_results.Providers,
			Domains:   dns_results.Domains,
		}
	} else {
		results.DNS = models.DnsResult{
			Result:    models.FailMessage,
			Reason:    dns_reason,
			Providers: dns_results.Providers,
			Domains:   dns_results.Domains,
		}
	}

	//* Check for external telemetry server (insights)
	cont, _ = client.GetViaURL("api/node/class/telemetryStatsServerP.json?rsp-subtree=full&query-target=children&target-subtree-class=telemetryExternalServer")
	if err != nil {
		return &results, err
	}
	var ext_telemetery_server_query models.TelemeteryStatsServerQuery
	err = json.Unmarshal(cont.Bytes(), &ext_telemetery_server_query)
	if err != nil {
		return &results, err
	}
	if ext_telemetery_server_query.TotalCount != "0" {
		results.Telemetry = models.BaseResult{
			Result: models.FailMessage,
			Reason: "External telemetry servers configured on fabric",
		}
	} else {
		results.Telemetry = models.BaseResult{
			Result: models.PassMessage,
			Reason: "",
		}
	}

	//* Overall result
	if nodes_valid && ntp_valid && results.DNS.Result == models.PassMessage && results.DeviceConnector.Result == models.PassMessage && results.NexusInsightsCloudConnector.Result == models.PassMessage && results.ApicVision.Result == models.PassMessage && results.Telemetry.Result == models.PassMessage {
		results.OverallResult = models.BaseResult{
			Result: models.PassMessage,
			Reason: "All prerequisites checks passed",
		}
	} else {
		results.OverallResult = models.BaseResult{
			Result: models.FailMessage,
			Reason: "One or more prerequisite checks failed",
		}
	}

	return &results, nil
}

// Generates excel report of onboarding results for an ACI site
func createAciReport(results *models.ApicResults, filename string) error {
	//* Initiate excel file
	f := excelize.NewFile()
	defer func() {
		if err := f.Close(); err != nil {
			log.Fatal(err)
		}
	}()

	err := f.SetSheetName("Sheet1", "Summary")
	if err != nil {
		log.Fatal(err)
	}

	excel_formatting := excel_formatting{
		styles: make(map[string]int),
	}
	err = createExcelStyles(f, &excel_formatting)
	if err != nil {
		log.Fatal(fmt.Errorf("an error occurred creating excel styles: %s", err))
	}
	disable_option := false
	f.SetSheetView("Summary", 0, &excelize.ViewOptions{
		ShowRowColHeaders: &disable_option,
		ShowGridLines:     &disable_option,
	})

	start_column := 3
	start_row := 2
	current_row := 2
	end_column := 10

	//* Title
	f.SetCellValue("Summary", fmt.Sprintf("%s2", toCharStr(start_column)), "Nexus Cloud Readiness Report")
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column-1), current_row), fmt.Sprintf("%s%d", toCharStr(end_column+1), current_row), excel_formatting.styles["title"])
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(end_column), current_row))

	//* Overall results
	current_row += 3
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), "Overall Assessment")
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+2), current_row))
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(start_column), current_row), excel_formatting.styles["overall_result_heading"])
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), results.OverallResult.Reason)
	if results.OverallResult.Result == models.PassMessage {
		f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+1), current_row), excel_formatting.styles["overall_result_pass"])
	} else {
		f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+1), current_row), excel_formatting.styles["overall_result_fail"])
	}
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+5), current_row))

	//* Site Info
	current_row += 3
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), "Site Details")
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+2), current_row))
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(start_column), current_row), excel_formatting.styles["heading"])
	current_row++
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), "Fabric Type")
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+2), current_row))
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(start_column), current_row), excel_formatting.styles["table_header"])
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), "ACI")
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), fmt.Sprintf("%s%d", toCharStr(end_column), current_row))
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), fmt.Sprintf("%s%d", toCharStr(end_column), current_row), excel_formatting.styles["table_cell"])
	current_row++
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), "Cluster")
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+2), current_row))
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+2), current_row), excel_formatting.styles["table_header_white_top"])
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), fmt.Sprintf("%s (%s)", results.Endpoint, results.FabricName))
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), fmt.Sprintf("%s%d", toCharStr(end_column), current_row))
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), fmt.Sprintf("%s%d", toCharStr(end_column), current_row), excel_formatting.styles["table_cell"])

	//* Readiness check results
	current_row += 3
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), "Readiness Checks")
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+2), current_row))
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(start_column), current_row), excel_formatting.styles["heading"])
	current_row += 1
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), "Check")
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+2), current_row))
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), "Result")
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+4), current_row))
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+5), current_row), "Reason")
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+5), current_row), fmt.Sprintf("%s%d", toCharStr(end_column), current_row))
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(end_column), current_row), excel_formatting.styles["table_header"])
	current_row += 1

	//* Nodes result
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), "Nodes")
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+2), current_row))
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+2), current_row), excel_formatting.styles["table_cell"])
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), results.NodeResult.Result)
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+4), current_row))
	if results.NodeResult.Result == models.PassMessage {
		f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+4), current_row), excel_formatting.styles["cell_pass"])
	} else {
		f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+4), current_row), excel_formatting.styles["cell_fail"])
	}
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+5), current_row), results.NodeResult.Reason)
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+5), current_row), fmt.Sprintf("%s%d", toCharStr(end_column), current_row))
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+5), current_row), fmt.Sprintf("%s%d", toCharStr(end_column), current_row), excel_formatting.styles["table_cell"])
	current_row += 1

	//* Device connector result
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), "Intersight Device Connector")
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+2), current_row))
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+2), current_row), excel_formatting.styles["table_cell"])
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), results.DeviceConnector.Result)
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+4), current_row))
	if results.DeviceConnector.Result == models.PassMessage {
		f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+4), current_row), excel_formatting.styles["cell_pass"])
	} else {
		f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+4), current_row), excel_formatting.styles["cell_fail"])
	}
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+5), current_row), results.DeviceConnector.Reason)
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+5), current_row), fmt.Sprintf("%s%d", toCharStr(end_column), current_row))
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+5), current_row), fmt.Sprintf("%s%d", toCharStr(end_column), current_row), excel_formatting.styles["table_cell"])
	current_row += 1

	//* NICC result
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), "Nexus Agent: Cloud Connector (NICC)")
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+2), current_row))
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+2), current_row), excel_formatting.styles["table_cell"])
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), results.NexusInsightsCloudConnector.Result)
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+4), current_row))
	if results.NexusInsightsCloudConnector.Result == models.PassMessage {
		f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+4), current_row), excel_formatting.styles["cell_pass"])
	} else {
		f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+4), current_row), excel_formatting.styles["cell_fail"])
	}
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+5), current_row), results.NexusInsightsCloudConnector.Reason)
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+5), current_row), fmt.Sprintf("%s%d", toCharStr(end_column), current_row))
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+5), current_row), fmt.Sprintf("%s%d", toCharStr(end_column), current_row), excel_formatting.styles["table_cell"])
	current_row += 1

	//* APIC vision result
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), "Nexus Agent: Cloud Vision")
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+2), current_row))
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+2), current_row), excel_formatting.styles["table_cell"])
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), results.ApicVision.Result)
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+4), current_row))
	if results.ApicVision.Result == models.PassMessage {
		f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+4), current_row), excel_formatting.styles["cell_pass"])
	} else {
		f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+4), current_row), excel_formatting.styles["cell_fail"])
	}
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+5), current_row), results.ApicVision.Reason)
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+5), current_row), fmt.Sprintf("%s%d", toCharStr(end_column), current_row))
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+5), current_row), fmt.Sprintf("%s%d", toCharStr(end_column), current_row), excel_formatting.styles["table_cell"])
	current_row += 1

	//* NTP result
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), "NTP")
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+2), current_row))
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+2), current_row), excel_formatting.styles["table_cell"])
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), results.NTP.Result)
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+4), current_row))
	if results.NTP.Result == models.PassMessage {
		f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+4), current_row), excel_formatting.styles["cell_pass"])
	} else {
		f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+4), current_row), excel_formatting.styles["cell_fail"])
	}
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+5), current_row), results.NTP.Reason)
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+5), current_row), fmt.Sprintf("%s%d", toCharStr(end_column), current_row))
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+5), current_row), fmt.Sprintf("%s%d", toCharStr(end_column), current_row), excel_formatting.styles["table_cell"])
	current_row += 1

	//* DNS result
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), "DNS")
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+2), current_row))
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+2), current_row), excel_formatting.styles["table_cell"])
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), results.DNS.Result)
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+4), current_row))
	if results.DNS.Result == models.PassMessage {
		f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+4), current_row), excel_formatting.styles["cell_pass"])
	} else {
		f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+4), current_row), excel_formatting.styles["cell_fail"])
	}
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+5), current_row), results.DNS.Reason)
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+5), current_row), fmt.Sprintf("%s%d", toCharStr(end_column), current_row))
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+5), current_row), fmt.Sprintf("%s%d", toCharStr(end_column), current_row), excel_formatting.styles["table_cell"])
	current_row += 1

	//* Nexus Dashboard Insights result
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), "Nexus Dashboard Insights Integrations")
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+2), current_row))
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+2), current_row), excel_formatting.styles["table_cell"])
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), results.Telemetry.Result)
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+4), current_row))
	if results.Telemetry.Result == models.PassMessage {
		f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+4), current_row), excel_formatting.styles["cell_pass"])
	} else {
		f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+4), current_row), excel_formatting.styles["cell_fail"])
	}
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+5), current_row), results.Telemetry.Reason)
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+5), current_row), fmt.Sprintf("%s%d", toCharStr(end_column), current_row))
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+5), current_row), fmt.Sprintf("%s%d", toCharStr(end_column), current_row), excel_formatting.styles["table_cell"])

	//* Node Table
	current_row += 3
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), "Node Table")
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+2), current_row))
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(start_column), current_row), excel_formatting.styles["heading"])
	current_row += 1
	column_widths := make(map[string]int)
	headers := []string{
		"Node",
		"Result",
		"Model",
		"Role",
		"Firmware",
		"Oob Mgmt Addr (IPv4/IPv6)",
		"NTP Servers",
		"Reason",
	}
	cell_padding := 6
	for i, header := range headers {
		column_widths[toCharStr(i+start_column)] = len(header) + cell_padding
		f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(i+start_column), current_row), header)
	}
	table_start := current_row
	current_row += 1

	for _, node := range results.Nodes {
		f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), node.NodeId)
		if column_widths[toCharStr(start_column)] < len(node.NodeId)+cell_padding {
			column_widths[toCharStr(start_column)] = len(node.NodeId) + cell_padding
		}
		f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+1), current_row), node.Result)
		if column_widths[toCharStr(start_column+1)] < len(node.Result)+cell_padding {
			column_widths[toCharStr(start_column+1)] = len(node.Result) + cell_padding
		}
		f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+2), current_row), node.Model)
		if column_widths[toCharStr(start_column+2)] < len(node.Model)+cell_padding {
			column_widths[toCharStr(start_column+2)] = len(node.Model) + cell_padding
		}
		f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), node.Role)
		if column_widths[toCharStr(start_column+3)] < len(node.Role)+cell_padding {
			column_widths[toCharStr(start_column+3)] = len(node.Role) + cell_padding
		}
		f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+4), current_row), node.Version)
		if column_widths[toCharStr(start_column+4)] < len(node.Version)+cell_padding {
			column_widths[toCharStr(start_column+4)] = len(node.Version) + cell_padding
		}
		f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+5), current_row), node.OobMgmtAddress)
		if column_widths[toCharStr(start_column+5)] < len(node.OobMgmtAddress)+cell_padding {
			column_widths[toCharStr(start_column+5)] = len(node.OobMgmtAddress) + cell_padding
		}
		ntp_servers := strings.Join(node.NtpServers, ", ")
		f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+6), current_row), ntp_servers)
		if column_widths[toCharStr(start_column+6)] < len(ntp_servers)+cell_padding {
			column_widths[toCharStr(start_column+6)] = len(ntp_servers) + cell_padding
		}
		f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+7), current_row), node.Reason)
		if column_widths[toCharStr(start_column+7)] < len(node.Reason)+cell_padding {
			column_widths[toCharStr(start_column+7)] = len(node.Reason) + cell_padding
		}

		current_row++
	}

	err = f.AddTable("Summary", fmt.Sprintf("%s%d:%s%d", toCharStr(start_column), table_start, toCharStr(end_column), current_row-1), &excelize.TableOptions{
		Name:      "topology",
		StyleName: "TableStyleLight9",
	})
	if err != nil {
		return err
	}
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), table_start+1), fmt.Sprintf("%s%d", toCharStr(end_column), current_row-1), excel_formatting.styles["table_columns"])
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), table_start), fmt.Sprintf("%s%d", toCharStr(end_column), table_start), excel_formatting.styles["table"])

	for column, width := range column_widths {
		f.SetColWidth("Summary", column, column, float64(width))
	}
	for idx, node := range results.Nodes {
		if node.Result == models.PassMessage {
			f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+1), table_start+idx+1), fmt.Sprintf("%s%d", toCharStr(start_column+1), table_start+idx+1), excel_formatting.styles["cell_pass"])
		} else {
			f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+1), table_start+idx+1), fmt.Sprintf("%s%d", toCharStr(start_column+1), table_start+idx+1), excel_formatting.styles["cell_fail"])
		}
	}

	//* DNS configuration
	current_row += 2
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), "DNS Configuration")
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+2), current_row))
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(start_column), current_row), excel_formatting.styles["heading"])
	current_row += 1
	dns_providers := ""
	for _, provider := range results.DNS.Providers {
		if dns_providers != "" {
			dns_providers += ", "
		}
		dns_providers += provider.Address
		if provider.Preferred {
			dns_providers += "(P)"
		}
	}
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), "Providers")
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+2), current_row))
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(start_column), current_row), excel_formatting.styles["table_header"])
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), dns_providers)
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), fmt.Sprintf("%s%d", toCharStr(end_column), current_row))
	if dns_providers != "" {
		f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), fmt.Sprintf("%s%d", toCharStr(end_column), current_row), excel_formatting.styles["table_cell"])
	} else {
		f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), fmt.Sprintf("%s%d", toCharStr(end_column), current_row), excel_formatting.styles["cell_fail"])
	}
	current_row += 1
	dns_domains := ""
	for _, domain := range results.DNS.Domains {
		if dns_domains != "" {
			dns_domains += ", "
		}
		dns_domains += domain.Name
		if domain.Default {
			dns_providers += "(D)"
		}
	}
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), "Domains")
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+2), current_row))
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+2), current_row), excel_formatting.styles["table_header_white_top"])
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), dns_domains)
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), fmt.Sprintf("%s%d", toCharStr(end_column), current_row))
	if dns_domains != "" {
		f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), fmt.Sprintf("%s%d", toCharStr(end_column), current_row), excel_formatting.styles["table_cell"])
	} else {
		f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+3), current_row), fmt.Sprintf("%s%d", toCharStr(end_column), current_row), excel_formatting.styles["cell_fail"])
	}

	//* Add report border
	current_row += 1
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column-1), start_row+1), fmt.Sprintf("%s%d", toCharStr(start_column-1), current_row-1), excel_formatting.styles["border_left"])
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(end_column+1), start_row+1), fmt.Sprintf("%s%d", toCharStr(end_column+1), current_row-1), excel_formatting.styles["border_right"])
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column-1), current_row), fmt.Sprintf("%s%d", toCharStr(start_column-1), current_row), excel_formatting.styles["border_bottom_left"])
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(end_column+1), current_row), fmt.Sprintf("%s%d", toCharStr(end_column+1), current_row), excel_formatting.styles["border_bottom_right"])
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(end_column), current_row), excel_formatting.styles["border_bottom"])

	// Save spreadsheet by the given path.
	if err := f.SaveAs(fmt.Sprintf("%s.xlsx", filename)); err != nil {
		log.Fatal(err)
	}
	return nil
}

// Iterates through NXOS devices and performs onboarding checks. The returned struct contains all of the results
func handleNxos(config *models.Config, pass string, matrix *configuration.Matrix) (*models.NxosResults, error) {
	var results models.NxosResults

	var wg sync.WaitGroup
	var mu sync.Mutex

	wg.Add(len(config.Nxos.Devices))

	for _, endpoint := range config.Nxos.Devices {
		go func(endpoint string) {
			log.Infof("Gathering switch details for %s", endpoint)
			defer wg.Done()
			var device models.NxosDeviceResult
			client, err := nxos.NewClient(endpoint, config.Nxos.Username, pass, true, config.Nxos.UseHttp, config.Nxos.Port)
			if err != nil {
				log.Errorf("could not create client for device: %s", endpoint)
				return
			}
			//* Perform login
			err = client.Login()
			if err != nil {
				log.Errorf("could not connect to device: %s", endpoint)
				device.MgmtIp = endpoint
				device.Result = models.FailMessage
				device.Reason = "Unable to connect to switch via NXAPI."
				mu.Lock()
				results.Devices = append(results.Devices, device)
				mu.Unlock()
				return
			}

			//* Get NXOS version
			var version_result models.NxosShowVersion
			err = client.GetDn("sys/showversion.json", &version_result, false)
			if err != nil {
				log.Errorf("could not retrieve version for device: %s", endpoint)
				return
			}
			device.Version.Value = version_result.SysmgrShowVersion.Attributes.NxosVersion

			//* Get switch name
			var top_system_result models.NxosTopSystem
			err = client.GetClass("topSystem.json", &top_system_result, false)
			if err != nil {
				log.Errorf("could not retrieve top system for device: %s", endpoint)
				return
			}
			device.Name = top_system_result.TopSystem.Attributes.Name

			//* Get switch model
			var equipment_result models.NxosEquipmentChassis
			err = client.GetDn("sys/ch.json", &equipment_result, false)
			if err != nil {
				log.Errorf("could not retrieve equipment details for device: %s", endpoint)
				return
			}
			device.Model.Value = equipment_result.EquipmentChassis.Attributes.Model
			device.Serial = equipment_result.EquipmentChassis.Attributes.Serial

			//* Get mgmt IP
			var system_table_result models.NxosAggregateSystemTable
			err = client.GetClass("aggregateSystemTable.json", &system_table_result, false)
			if err != nil {
				log.Errorf("could not retrieve aggregate system table for device: %s", endpoint)
				return
			}
			device.MgmtIp = system_table_result.AggregateSystemTable.Attributes.MgmtIp

			// Model cleanup
			device.Model.Value = strings.Replace(device.Model.Value, "N9K-C", "", 1)

			if !formatting.InArray(device.Model.Value, matrix.Nxos.Switch.Models.Supported) {
				device.Result = models.FailMessage
				device.Model.Result = models.FailMessage
				device.Model.Reason = "Switch model not currently supported."
			} else {
				device.Model.Result = models.PassMessage
			}

			if !formatting.InArray(device.Version.Value, matrix.Nxos.Switch.Versions) {
				device.Result = models.FailMessage
				device.Version.Result = models.FailMessage
				device.Version.Reason = "Firmware version not currently supported."
			} else {
				device.Version.Result = models.PassMessage
			}

			//* Get DNS Providers for management VRF
			var dns_provider_result []models.NxosDnsProvider
			err = client.GetDn("sys/dns/prof-[management].json?query-target=subtree&target-subtree-class=dnsProvider", &dns_provider_result, true)
			if err != nil {
				log.Errorf("could not retrieve dns providers for device: %s", endpoint)
				return
			}
			for _, provider := range dns_provider_result {
				device.Dns.Providers = append(device.Dns.Providers, models.DnsProvider{
					Address: provider.DnsProvider.Attributes.Addr,
				})
			}

			if len(device.Dns.Providers) == 0 {
				device.Dns.Reason += "No DNS providers found for management VRF."
				device.Dns.Result = models.FailMessage
				device.Result = models.FailMessage
			}

			//* Get DNS Domains for management VRF
			var dns_domain_result []models.NxosDnsDomain
			err = client.GetDn("sys/dns/prof-[management].json?query-target=subtree&target-subtree-class=dnsDom", &dns_domain_result, true)
			if err != nil {
				log.Errorf("could not retrieve dns domains for device: %s", endpoint)
				return
			}
			for _, domain := range dns_domain_result {
				device.Dns.Domains = append(device.Dns.Domains, models.DnsDomainResult{
					Name: domain.DnsDom.Attributes.Name,
				})
			}

			if len(device.Dns.Domains) == 0 {
				if device.Dns.Reason != "" {
					device.Dns.Reason += " "
				}
				device.Dns.Reason += "No configured search domain found for management VRF."
				device.Dns.Result = models.FailMessage
				device.Result = models.FailMessage
			}

			if device.Dns.Result != models.FailMessage {
				device.Dns.Result = models.PassMessage
				device.Dns.Reason = "Configured"
			}

			//* Get NTP details
			var ntp_result []models.NxosNtpProvider
			err = client.GetClass("datetimeNtpProvider.json?rsp-subtree=full", &ntp_result, true)
			if err != nil {
				log.Errorf("could not retrieve ntp config for device: %s", endpoint)
				return
			}
			for _, ntp_provider := range ntp_result {
				if len(ntp_provider.DatetimeNtpProvider.Children) > 0 {
					if ntp_provider.DatetimeNtpProvider.Attributes.Preferred != "no" {
						device.Ntp.Providers = append(device.Ntp.Providers, fmt.Sprintf("%s(P)", ntp_provider.DatetimeNtpProvider.Attributes.Name))
					} else {
						device.Ntp.Providers = append(device.Ntp.Providers, ntp_provider.DatetimeNtpProvider.Attributes.Name)
					}
				}
			}

			if len(device.Ntp.Providers) == 0 {
				device.Ntp.Reason = "No working NTP providers configured."
				device.Ntp.Result = models.FailMessage
				device.Result = models.FailMessage
			} else {
				device.Ntp.Result = models.PassMessage
				device.Ntp.Reason = "Configured"
			}

			//* Check if telemetry feature is enabled
			var telemetry_feature_result []interface{}
			err = client.GetDn("sys/fm/telemetry.json", &telemetry_feature_result, true)
			if err != nil {
				log.Errorf("could not retrieve telemetry feature info for device: %s", endpoint)
				return
			}

			if len(telemetry_feature_result) == 0 {
				device.Telemetry = models.BaseResult{
					Result: models.PassMessage,
					Reason: "Not Present",
				}
			} else {
				device.Telemetry = models.BaseResult{
					Result: models.FailMessage,
					Reason: "Existing telemetry configuration exists.",
				}
				device.Result = models.FailMessage
			}

			//* Check if cdp is enabled
			var cdp_instance_result models.CdpInstance
			err = client.GetDn("sys/cdp/inst.json", &cdp_instance_result, false)
			if err != nil {
				log.Errorf("could not retrieve cdp instance for device: %s", endpoint)
				return
			}

			//* Check if lldp is enabled
			var lldp_fm_result []models.FeatureLldp
			err = client.GetDn("sys/fm/lldp.json", &lldp_fm_result, true)
			if err != nil {
				log.Errorf("could not retrieve lldp feature info for device: %s", endpoint)
				return
			}

			//* Store discovery protocol results
			if (len(lldp_fm_result) > 0 && lldp_fm_result[0].FeatureLldp.Attributes.AdminSt == "enabled") || cdp_instance_result.CdpInstance.Attributes.AdminSt == "enabled" {
				device.DiscoveryProtocol = models.BaseResult{
					Result: models.PassMessage,
				}
				device.DiscoveryProtocol.Reason = "Enabled"
			} else {
				device.DiscoveryProtocol = models.BaseResult{
					Result: models.FailMessage,
					Reason: "CDP and LLDP are both currently disabled.",
				}
				device.Result = models.FailMessage
			}

			//* Get Intersight Config
			// intersight_config, err := client.GetCliShow("show run intersight")
			// if err != nil {
			// 	log.Error(err)
			// }
			// formatting.PrettyPrint(intersight_config)

			//* Check if intersight can be resolved
			ping_result, err := client.SendCliConf("ping svc.intersight.com vrf management")
			if err != nil {
				log.Error(err)
			}
			if strings.Contains(ping_result.InsApi.Outputs.Output.Body, "Invalid host") {
				device.PingTest = models.BaseResult{
					Result: models.FailMessage,
					Reason: "Unable to resolve svc.intersight.com on management vrf.",
				}
				device.Result = models.FailMessage
			} else {
				device.PingTest = models.BaseResult{
					Result: models.PassMessage,
				}
				device.PingTest.Reason = "Resolved"
			}
			if device.Result == models.FailMessage && device.Reason == "" {
				device.Reason = "Highlighted columns failed to meet prerequisite requirements"
			} else if device.Result == "" && device.Reason == "" {
				device.Result = models.PassMessage
			}
			mu.Lock()
			results.Devices = append(results.Devices, device)
			mu.Unlock()
		}(endpoint)
	}
	wg.Wait()
	for _, device := range results.Devices {
		if device.Result == models.FailMessage {
			results.OverallResult.Result = models.FailMessage
			results.OverallResult.Reason = "One or more switches did not meet all suggested prerequisites.  See table below for details."
			break
		}
	}
	if results.OverallResult.Reason == "" {
		results.OverallResult = models.BaseResult{
			Result: models.PassMessage,
			Reason: "All prerequisites checks passed",
		}
	}
	return &results, nil
}

func createNxosReport(results *models.NxosResults, filename string) error {
	//* Initiate excel file
	f := excelize.NewFile()
	defer func() {
		if err := f.Close(); err != nil {
			log.Fatal(err)
		}
	}()

	err := f.SetSheetName("Sheet1", "Summary")
	if err != nil {
		log.Fatal(err)
	}

	excel_formatting := excel_formatting{
		styles: make(map[string]int),
	}
	err = createExcelStyles(f, &excel_formatting)
	if err != nil {
		log.Fatal(fmt.Errorf("an error occurred creating excel styles: %s", err))
	}
	disable_option := false
	f.SetSheetView("Summary", 0, &excelize.ViewOptions{
		ShowRowColHeaders: &disable_option,
		ShowGridLines:     &disable_option,
	})

	start_column := 3
	start_row := 2
	current_row := 2
	end_column := 14

	//* Title
	f.SetCellValue("Summary", fmt.Sprintf("%s2", toCharStr(start_column)), "Nexus Cloud Readiness Report")
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column-1), current_row), fmt.Sprintf("%s%d", toCharStr(end_column+1), current_row), excel_formatting.styles["title"])
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(end_column), current_row))

	//* Overall results
	current_row += 3
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), "Overall Assessment")
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+1), current_row))
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(start_column), current_row), excel_formatting.styles["overall_result_heading"])
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+2), current_row), results.OverallResult.Reason)
	if results.OverallResult.Result == models.PassMessage {
		f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+2), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+1), current_row), excel_formatting.styles["overall_result_pass"])
		f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+2), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+5), current_row))
	} else {
		f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+2), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+1), current_row), excel_formatting.styles["overall_result_fail"])
		f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+2), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+6), current_row))
	}

	//* Switch Table
	current_row += 3
	f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), "Switch Table")
	f.MergeCell("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(start_column+2), current_row))
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(start_column), current_row), excel_formatting.styles["heading"])
	current_row += 1
	column_widths := make(map[string]int)
	headers := []string{
		"Name",
		"Result",
		"Mgmt IP",
		"Model",
		"Serial",
		"Version",
		"DNS",
		"NTP",
		"Existing Telemetry",
		"Discovery Protocols",
		"Ping Test",
		"Reason(s)",
	}
	cell_padding := 6
	for i, header := range headers {
		column_widths[toCharStr(i+start_column)] = len(header) + cell_padding
		f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(i+start_column), current_row), header)
	}
	table_start := current_row
	current_row += 1

	for _, device := range results.Devices {
		device_column := start_column
		f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(device_column), current_row), device.Name)
		if column_widths[toCharStr(device_column)] < len(device.Name)+cell_padding {
			column_widths[toCharStr(device_column)] = len(device.Name) + cell_padding
		}
		device_column++
		f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(device_column), current_row), device.Result)
		if column_widths[toCharStr(device_column)] < len(device.Result)+cell_padding {
			column_widths[toCharStr(device_column)] = len(device.Result) + cell_padding
		}
		device_column++
		f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(device_column), current_row), device.MgmtIp)
		if column_widths[toCharStr(device_column)] < len(device.MgmtIp)+cell_padding {
			column_widths[toCharStr(device_column)] = len(device.MgmtIp) + cell_padding
		}
		device_column++
		f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(device_column), current_row), device.Model.Value)
		if column_widths[toCharStr(device_column)] < len(device.Model.Value)+cell_padding {
			column_widths[toCharStr(device_column)] = len(device.Model.Value) + cell_padding
		}
		device_column++
		f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(device_column), current_row), device.Serial)
		if column_widths[toCharStr(device_column)] < len(device.Serial)+cell_padding {
			column_widths[toCharStr(device_column)] = len(device.Serial) + cell_padding
		}
		device_column++
		f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(device_column), current_row), device.Version.Value)
		if column_widths[toCharStr(device_column)] < len(device.Version.Value)+cell_padding {
			column_widths[toCharStr(device_column)] = len(device.Version.Value) + cell_padding
		}
		device_column++
		f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(device_column), current_row), device.Dns.Reason)
		if column_widths[toCharStr(device_column)] < len(device.Dns.Reason)+cell_padding {
			column_widths[toCharStr(device_column)] = len(device.Dns.Reason) + cell_padding
		}
		device_column++
		f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(device_column), current_row), device.Ntp.Reason)
		if column_widths[toCharStr(device_column)] < len(device.Ntp.Reason)+cell_padding {
			column_widths[toCharStr(device_column)] = len(device.Ntp.Reason) + cell_padding
		}
		device_column++
		f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(device_column), current_row), device.Telemetry.Reason)
		if column_widths[toCharStr(device_column)] < len(device.Telemetry.Reason)+cell_padding {
			column_widths[toCharStr(device_column)] = len(device.Telemetry.Reason) + cell_padding
		}
		device_column++
		f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(device_column), current_row), device.DiscoveryProtocol.Reason)
		if column_widths[toCharStr(device_column)] < len(device.DiscoveryProtocol.Reason)+cell_padding {
			column_widths[toCharStr(device_column)] = len(device.DiscoveryProtocol.Reason) + cell_padding
		}
		device_column++
		f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(device_column), current_row), device.PingTest.Reason)
		if column_widths[toCharStr(device_column)] < len(device.PingTest.Reason)+cell_padding {
			column_widths[toCharStr(device_column)] = len(device.PingTest.Reason) + cell_padding
		}
		device_column++
		f.SetCellValue("Summary", fmt.Sprintf("%s%d", toCharStr(device_column), current_row), device.Reason)
		if column_widths[toCharStr(device_column)] < len(device.Reason)+cell_padding {
			column_widths[toCharStr(device_column)] = len(device.Reason) + cell_padding
		}

		current_row++
	}

	err = f.AddTable("Summary", fmt.Sprintf("%s%d:%s%d", toCharStr(start_column), table_start, toCharStr(end_column), current_row-1), &excelize.TableOptions{
		Name:      "topology",
		StyleName: "TableStyleLight9",
	})
	if err != nil {
		return err
	}
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), table_start+1), fmt.Sprintf("%s%d", toCharStr(end_column), current_row-1), excel_formatting.styles["table_columns"])
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), table_start), fmt.Sprintf("%s%d", toCharStr(end_column), table_start), excel_formatting.styles["table"])

	for column, width := range column_widths {
		f.SetColWidth("Summary", column, column, float64(width))
	}
	for idx, device := range results.Devices {
		if device.Result == models.PassMessage {
			f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+1), table_start+idx+1), fmt.Sprintf("%s%d", toCharStr(start_column+1), table_start+idx+1), excel_formatting.styles["cell_pass"])
		} else {
			f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+1), table_start+idx+1), fmt.Sprintf("%s%d", toCharStr(start_column+1), table_start+idx+1), excel_formatting.styles["cell_fail"])
		}
		if device.Model.Result == models.FailMessage {
			c := formatting.GetIndex("Model", headers)
			f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+c), table_start+idx+1), fmt.Sprintf("%s%d", toCharStr(start_column+c), table_start+idx+1), excel_formatting.styles["cell_fail"])
		}
		if device.Version.Result == models.FailMessage {
			c := formatting.GetIndex("Version", headers)
			f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+c), table_start+idx+1), fmt.Sprintf("%s%d", toCharStr(start_column+c), table_start+idx+1), excel_formatting.styles["cell_fail"])
		}
		if device.Dns.Result == models.FailMessage {
			c := formatting.GetIndex("DNS", headers)
			f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+c), table_start+idx+1), fmt.Sprintf("%s%d", toCharStr(start_column+c), table_start+idx+1), excel_formatting.styles["cell_fail"])
		}
		if device.Ntp.Result == models.FailMessage {
			c := formatting.GetIndex("NTP", headers)
			f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+c), table_start+idx+1), fmt.Sprintf("%s%d", toCharStr(start_column+c), table_start+idx+1), excel_formatting.styles["cell_fail"])
		}
		if device.Telemetry.Result == models.FailMessage {
			c := formatting.GetIndex("Existing Telemetry", headers)
			f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+c), table_start+idx+1), fmt.Sprintf("%s%d", toCharStr(start_column+c), table_start+idx+1), excel_formatting.styles["cell_fail"])
		}
		if device.DiscoveryProtocol.Result == models.FailMessage {
			c := formatting.GetIndex("Discovery Protocols", headers) + 1
			f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+c), table_start+idx+1), fmt.Sprintf("%s%d", toCharStr(start_column+c), table_start+idx+1), excel_formatting.styles["cell_fail"])
		}
		if device.PingTest.Result == models.FailMessage {
			c := formatting.GetIndex("Ping Test", headers)
			f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column+c), table_start+idx+1), fmt.Sprintf("%s%d", toCharStr(start_column+c), table_start+idx+1), excel_formatting.styles["cell_fail"])
		}
	}

	//* Add report border
	current_row += 1
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column-1), start_row+1), fmt.Sprintf("%s%d", toCharStr(start_column-1), current_row-1), excel_formatting.styles["border_left"])
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(end_column+1), start_row+1), fmt.Sprintf("%s%d", toCharStr(end_column+1), current_row-1), excel_formatting.styles["border_right"])
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column-1), current_row), fmt.Sprintf("%s%d", toCharStr(start_column-1), current_row), excel_formatting.styles["border_bottom_left"])
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(end_column+1), current_row), fmt.Sprintf("%s%d", toCharStr(end_column+1), current_row), excel_formatting.styles["border_bottom_right"])
	f.SetCellStyle("Summary", fmt.Sprintf("%s%d", toCharStr(start_column), current_row), fmt.Sprintf("%s%d", toCharStr(end_column), current_row), excel_formatting.styles["border_bottom"])

	// Save spreadsheet by the given path.
	if err := f.SaveAs(fmt.Sprintf("%s.xlsx", filename)); err != nil {
		log.Fatal(err)
	}
	return nil
}

func init() {
	log.SetLevel(log.InfoLevel)
}

func main() {
	//* Read configuration file from supplied filename
	config_file := flag.String("filename", "config.yaml", "yaml config filename")
	output_file := flag.String("out", "nexus_cloud_readiness", "output filename")
	flag.Parse()
	config, err := readConf(*config_file)
	if err != nil {
		log.Fatal(err)
	}

	//* Retrieve support matrix
	log.Println("Loading matrix")
	matrix, err := configuration.GetConfigurationMatrix()
	if err != nil {
		log.Fatal(fmt.Errorf("Error loading matrix: %s", err))
	}

	//* Retrieve seed password from user (ACI or NXOS)
	fmt.Print("Password: ")
	bytepw, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		os.Exit(1)
	}
	pass := string(bytepw)
	fmt.Println()

	//* Validate config data
	if config.Aci != (models.AciConfig{}) {
		log.Info("ACI data found")
		aciResults, err := handleAci(config, pass, matrix)
		if err != nil {
			log.Fatal(fmt.Errorf("an error occurred collecting ACI data: %s", err))
		}
		log.Info("ACI data colelcted. Creating final report...")
		err = createAciReport(aciResults, *output_file)
		if err != nil {
			log.Fatalf("An error occurred writing excel report: %s", err)
		}
	} else if len(config.Nxos.Devices) > 0 {
		log.Info("Found NXOS config data")
		nxos_results, err := handleNxos(config, pass, matrix)
		if err != nil {
			log.Fatal(fmt.Errorf("an error occurred collecting nxos data: %s", err))
		}
		log.Info("Device data colelcted. Creating final report...")
		err = createNxosReport(nxos_results, *output_file)
		if err != nil {
			log.Fatalf("An error occurred writing excel report: %s", err)
		}
	} else {
		log.Error(fmt.Errorf("no valid configuration found in %s", *config_file))
	}
	log.Info("Nexus Cloud readiness report successfully created.")
}
