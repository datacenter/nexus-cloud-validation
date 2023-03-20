# Nexus Cloud Validation

The purpose of this script is to validate a list of standalone Nexus 9K switches or an ACI fabric meets the prerequisites for Nexus Cloud onboarding.  The script aims to check all of the prerequisite requirements listed in the Nexus Cloud [getting started](https://docs.nexuscloud.com/story/nexus-cloud-getting-started/) documentation.

The output of the script is an excel file displaying the results of all tests performed and highlights any prerequisites that have not been met. It is important that **_ALL_** prerequisites are met to ensure a smooth onboarding experience.

Please open an issue on this repo if you run into any issues using this script.

## Getting started

Go to the [releases](https://wwwin-github.cisco.com/robbeck/nc_onboarding/releases) page of this repository and download the **latest** version for the target OS and architecture you plan to run the script on.  For example, PC users would likely choose the zip file ending in `windows_amd64.zip` while Mac users with Apple silicon would chose `darwin_arm64.zip`. Once downloaded, extract the contents of the zip file.

A `yaml` file is required for the script to know how to access the target fabric.  Below are example yaml files:

### ACI

```yaml
aci:
  endpoint: sandboxapicdc.cisco.com
  username: admin
```

`endpoint` - the IP or hostname of an APIC controller

`username` - the username used for querying the fabric config.  While the script doesn't alter any configuration, an account with **elevated** privileges is **required** to check the status of the device connector.

### NXOS
 ```yaml
nxos:
  username: admin
  use_http: no
  port: 443
  devices:
    - "172.16.18.65"
    - "172.16.18.66"
    - "172.16.18.67"
 ```

 `username` - the username used for querying the fabric config. This username should exist on all devices listed. The script performs a `ping` cli command to verify Intersight services are resolvable on the management vrf so the username needs the required privileges to perform this action.

 `use_http` - (Optional) specifies whether to use `http` for NXAPI. The NXOS feature `ssh-server` is required to be enabled for `https` to be supported. Defaults to `no` meaning it uses `https`.

 `port` - (Optional) port used for NXAPI communication. Defaults to `80` for `http` and `443` for `https`.

 `devices` - List of IPs or hostnames of switches targeted for analysis.

 > NXOS analysis requires the **nxapi** feature be **enabled** on all devices listed.

 Create a yaml file in the same directory as the extracted file downloaded above.  The contents should match one of the two examples above but with your site specific data.

 ## Using the script

 Open a command prompt and navigate to the directory of the extracted zip file you downloaded from this repo.

 Below is an example execution of the script via command prompt.

 ```sh
./nexus_cloud_validation -filename config.yml -out results
 ```

 `-filename` - (required) the path to the configuration yaml file created previously
 
 `-out` - (optional) the filename for the results report.

 ### Entering a password

 The script will interactively prompt you for the password associated with the username provided in the configuration yaml file. In the case of Nexus 9K standalone, the assumption is the same username/password combination is supported on all devices listed in the configuration yaml file.