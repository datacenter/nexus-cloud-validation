package formatting

import (
	"encoding/json"
	"log"
	"regexp"
	"strconv"
	"strings"
)

func PrettyPrint(object interface{}) {
	output, _ := json.MarshalIndent(object, "", "    ")
	log.Printf("%s", string(output))
}

func CompareFwVersions(v1 string, v2 string) (int, error) {
	r, _ := regexp.Compile(`[a-zA-Z]+`)
	//* Compare major versions
	mj1, err := strconv.ParseFloat(strings.Split(v1, "(")[0], 64)
	if err != nil {
		return 0, err
	}
	mj2, err := strconv.ParseFloat(strings.Split(v2, "(")[0], 64)
	if err != nil {
		return 0, err
	}
	if mj1 != mj2 {
		return -1, nil
	}
	//* Check if letter version
	// log.Printf("v1: %s v2: %s v1Match: %v v2Match: %v", v1, v2, r.MatchString(v1), r.MatchString(v2))
	if r.MatchString(v1) || r.MatchString(v2) {
		digits_match := regexp.MustCompile(`[0-9]*`)
		// letters_match := regexp.MustCompile(`\d*`)
		mn1 := strings.Split(v1, "(")[1]
		mn1 = strings.Replace(mn1, ")", "", -1)
		mn2 := strings.Split(v2, "(")[1]
		mn2 = strings.Replace(mn2, ")", "", -1)

		mn1_ver, err := strconv.ParseFloat(digits_match.FindString(mn1), 64)
		if err != nil {
			return 0, err
		}
		mn2_ver, err := strconv.ParseFloat(digits_match.FindString(mn2), 64)
		if err != nil {
			return 0, err
		}
		if mn1_ver > mn2_ver {
			return 1, nil
		} else if mn1_ver < mn2_ver {
			return -1, nil
		}
		if r.FindString(mn1) > r.FindString(mn2) {
			return 1, nil
		} else if r.FindString(mn1) < r.FindString(mn2) {
			return -1, nil
		}

	}
	return 0, nil
}

func GetIndex(target string, items []string) int {
	for idx, v := range items {
		if v == target {
			return idx
		}
	}
	return -1
}

func InArray(target string, arr []string) bool {
	match := false
	for _, entry := range arr {
		if target == entry {
			match = true
			break
		}
	}
	return match
}
