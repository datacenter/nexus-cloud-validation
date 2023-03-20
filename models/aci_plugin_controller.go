package models

import (
	"strconv"
	"strings"
)

type ApPlugin struct {
	ApPlugin struct {
		Attributes struct {
			Annotation         string
			ApicMode           string `json:"apicMode"`
			AppCtxRoot         string `json:"appCtxRoot"`
			AppId              string `json:"appId"`
			AppType            string `json:"appType"`
			Cert               string
			ChildAction        string `json:"childAction"`
			ClusterManagerType string `json:"clusterManagerType"`
			ConfigInfo         string `json:"configInfo"`
			ConfigIssues       string `json:"configIssues"`
			ConfigSt           string `json:"configSt"`
			CtrlVersion        string `json:"ctrlVersion"`
			Description        string
			Dn                 string
			DockerImage        string `json:"dockerImage"`
			Name               string
			PluginSt           string `json:"pluginSt"`
			OperState          string `json:"operSt"`
			Role               string
			Status             string
			TargetVersion      string `json:"targetVersion"`
			Version            string
		}
		Children []FaultCounts
	} `json:"apPlugin"`
}

type FaultCounts struct {
	FaultCounts struct {
		Attributes struct {
			Critical string `json:"crit"`
			Major    string `json:"maj"`
			Minor    string
			Status   string
			Warn     string
		}
	} `json:"faultCounts"`
}

type ApPluginQuery struct {
	TotalCount string `json:"totalCount"`
	Imdata     []ApPlugin
}

func (ap *ApPlugin) FaultCount() (int, error) {
	faults := 0
	count, err := strconv.ParseInt(ap.ApPlugin.Children[0].FaultCounts.Attributes.Critical, 10, 64)
	if err != nil {
		return faults, err
	}
	faults += int(count)
	count, err = strconv.ParseInt(ap.ApPlugin.Children[0].FaultCounts.Attributes.Major, 10, 64)
	if err != nil {
		return faults, err
	}
	faults += int(count)
	count, err = strconv.ParseInt(ap.ApPlugin.Children[0].FaultCounts.Attributes.Minor, 10, 64)
	if err != nil {
		return faults, err
	}
	faults += int(count)
	count, err = strconv.ParseInt(ap.ApPlugin.Children[0].FaultCounts.Attributes.Warn, 10, 64)
	if err != nil {
		return faults, err
	}
	faults += int(count)

	return faults, nil
}

func getSplitVersion(v string) ([]int, error) {
	var versions []int
	for _, s := range strings.Split(v, ".") {
		i, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return versions[:], err
		}
		versions = append(versions, int(i))
	}
	return versions, nil
}

func (ap *ApPlugin) HasValidVersion(supported_versions []string) (bool, error) {
	for _, version := range supported_versions {
		version_expanded, err := getSplitVersion(version)
		if err != nil {
			return false, err
		}
		check_expanded, err := getSplitVersion(ap.ApPlugin.Attributes.Version)
		if err != nil {
			return false, err
		}
		equal := false
		for idx, v := range version_expanded {
			if check_expanded[idx] > v {
				return true, nil
			} else if check_expanded[idx] == v {
				equal = true
			} else {
				equal = false
				break
			}
		}
		if equal {
			return true, nil
		}
	}
	return false, nil
}
