package models

type NxosLoginPayload struct {
	User struct {
		Attributes struct {
			Name     string `json:"name"`
			Password string `json:"pwd"`
		} `json:"attributes"`
	} `json:"aaaUser"`
}

func (l *NxosLoginPayload) CreateLogin(username string, password string) {
	l.User.Attributes.Name = username
	l.User.Attributes.Password = password
}

type NxosLoginResponse struct {
	Login struct {
		Attributes struct {
			Token      string
			Username   string `json:"userName"`
			RemoteUser string `json:"remoteUser"`
			Version    string
		}
	} `json:"aaaLogin"`
}
