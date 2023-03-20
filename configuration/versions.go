package configuration

import (
	"gopkg.in/yaml.v3"
)

type Matrix struct {
	Aci struct {
		Controller struct {
			Versions []string
		}
		Switch struct {
			Versions []string
			Models   struct {
				Supported []string
			}
		}
		Device_Connector struct {
			Versions []string
		} `yaml:"device_connector"`
		Nexus_Cloud_Insights_Cloud_Connector struct {
			Versions []string
		} `yaml:"nexus_cloud_insights_cloud_connector"`
		Apic_Vision_App struct {
			Versions []string
		} `yaml:"apic_vision_app"`
	}
	Nxos struct {
		Switch struct {
			Versions []string
			Models   struct {
				Supported []string
			}
		}
	}
}

func GetConfigurationMatrix() (*Matrix, error) {
	var matrix Matrix
	config_yaml := `
aci:
    controller:
        versions:
          - 5.2(7f)
          - 5.2(7g)
          - 6.0(2h)
    switch:
        versions:
            - 15.2(7f)
            - 15.2(7g)
            - 16.0(2h)
        models:
            supported:
                - 93108TC-EX
                - 93108TC-FX
                - 93120TX
                - 93180LC-EX
                - 93180YC-EX
                - 93180YC-FX
                - 93180YC-FX3
                - 93240YC-FX2
                - 9332C
                - 9336C-FX2
                - 9348GC-FXP
                - 9364C
                - 93600CD-GX
                - '9504'
                - '9508'
                - '9516'
    device_connector:
        versions:
            - 1.0.11-1833
    nexus_cloud_insights_cloud_connector:
        versions:
            - '3.0.0.183'
    apic_vision_app:
        versions:
            - '5.2.33'
nxos:
    switch:
        versions:
            - 10.2(4)
        models:
            supported:
                - 92348GC-X
                - 93108TC-EX
                - 93108TC-EX-24
                - 93108TC-FX
                - 93108TC-FX-24
                - 93108TC-FX3P
                - 9316D-GX
                - 93180YC-EX
                - 93180YC-EX-24
                - 93180YC-FX
                - 93180YC-FX-24
                - 93180YC-FX3
                - 93180YC-FX3S
                - 93216TC-FX2
                - 93240YC-FX2
                - 9332C
                - 9332D-GX2B
                - 93360YC-FX2
                - 9336C-FX2
                - 9336C-FX2-E
                - 9348D-GX2A
                - 9348GC-FXP
                - 93600CD-GX
                - 9364C
                - 9364C-GX
                - 9364D-GX2A
                - '9408'
                - '9504'
                - '9508'
                - '9516'
                - '9808'
                - 36180YC-R
                - 3636C-R

`
	err := yaml.Unmarshal([]byte(config_yaml), &matrix)
	return &matrix, err
}
