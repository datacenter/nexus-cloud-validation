package models

import (
	"strconv"
	"strings"
)

type ConnectorVersion struct {
	Version     string
	BuildNumber string
	Branch      string
	GitCommit   string
	BuildHost   string
	BuildTime   string
	User        string
	GoToolChain string
}

func (cv *ConnectorVersion) HasValidVersion(supported_versions []string) (bool, error) {
	for _, version := range supported_versions {
		v1_split := strings.Split(cv.Version, "-")
		v2_split := strings.Split(version, "-")

		version_expanded, err := getSplitVersion(v2_split[0])
		if err != nil {
			return false, err
		}
		check_expanded, err := getSplitVersion(v1_split[0])
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
			v1_mn, err := strconv.ParseFloat(v1_split[1], 64)
			if err != nil {
				return false, err
			}
			v2_mn, err := strconv.ParseFloat(v2_split[1], 64)
			if err != nil {
				return false, err
			}
			if v1_mn > v2_mn || v1_mn == v2_mn {
				return true, nil
			}
		}
	}
	return false, nil
}
