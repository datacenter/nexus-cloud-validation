package models

type Config struct {
	Aci  AciConfig
	Nxos NxosConfig
}

type AciConfig struct {
	Endpoint string
	Username string
	Pod      string
}

type NxosConfig struct {
	Username string
	UseHttp  bool `yaml:"use_http"`
	Port     int
	Devices  []string
}
