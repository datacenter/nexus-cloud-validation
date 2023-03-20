package models

import (
	"encoding/json"

	log "github.com/sirupsen/logrus"
)

type NxosBaseResponse struct {
	Count  string        `json:"totalCount"`
	Imdata []interface{} `json:"imdata"`
}

func (b *NxosBaseResponse) Bytes(want_array bool) []byte {
	if want_array {
		buf, err := json.Marshal(b.Imdata)
		if err != nil {
			log.Error(err)
		}
		return buf
	} else {
		buf, err := json.Marshal(b.Imdata[0])
		if err != nil {
			log.Error(err)
		}
		return buf
	}
}
