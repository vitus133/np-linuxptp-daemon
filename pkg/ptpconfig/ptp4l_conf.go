package ptpconfig

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/golang/glog"

	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/config"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/event"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/synce"

	ptpv1 "github.com/k8snetworkplumbingwg/ptp-operator/api/v1"
)

const (
	// GlobalSectionName is the ptp4l global section header.
	GlobalSectionName = "[global]"
	// NmeaSectionName is the ptp4l NMEA section header.
	NmeaSectionName = "[nmea]"
	// UnicastSectionName is the ptp4l unicast section header.
	UnicastSectionName = "[unicast_master_table]"
)

type ptp4lConfOption struct {
	key   string
	value string
}

type ptp4lConfSection struct {
	sectionName string
	options     []ptp4lConfOption
}

// Ptp4lConf is a structure to represent a parsed ptpconfig,
// which can then be rendered to a string again.
type Ptp4lConf struct {
	sections        []ptp4lConfSection
	profileName     string
	clockType       event.ClockType
	gnssSerialPort  string // gnss serial port
	leapFileEnabled bool
}

// PopulatePtp4lConf takes as input a PtpProfile.Ptp4lConf string and outputs as ptp4lConf struct
func (conf *Ptp4lConf) PopulatePtp4lConf(cfg *string) error {
	var currentSectionName string
	conf.sections = make([]ptp4lConfSection, 0)
	hasSlaveConfigDefined := false
	ifaceCount := 0
	if cfg != nil {
		for _, line := range strings.Split(*cfg, "\n") {
			line = strings.TrimSpace(line)
			// Skip empty lines and comments
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			} else if strings.HasPrefix(line, "[") {
				currentLine := strings.Split(line, "]")
				if len(currentLine) < 2 {
					return errors.New("Section missing closing ']': " + line)
				}
				currentSectionName = fmt.Sprintf("%s]", currentLine[0])
				if currentSectionName != GlobalSectionName && currentSectionName != NmeaSectionName && currentSectionName != UnicastSectionName {
					ifaceCount++
				}
				conf.setOption(currentSectionName, "", "", false)
			} else {
				split := strings.IndexByte(line, ' ')
				if split > 0 {
					key := line[:split]
					value := strings.TrimSpace(line[split:])
					conf.setOption(currentSectionName, key, value, false)
					if (key == "masterOnly" && value == "0" && currentSectionName != GlobalSectionName) ||
						(key == "serverOnly" && value == "0") ||
						(key == "slaveOnly" && value == "1") ||
						(key == "clientOnly" && value == "1") {
						hasSlaveConfigDefined = true
					}
					if key == "leapfile" {
						conf.leapFileEnabled = true
					}
				}
			}
		}
	}

	if !hasSlaveConfigDefined {
		conf.clockType = event.GM
	} else if ifaceCount > 1 {
		conf.clockType = event.BC
	} else {
		conf.clockType = event.OC
	}

	return nil
}

// ExtendGlobalSection extends Ptp4lConf struct with fields not from ptp4lConf
func (conf *Ptp4lConf) ExtendGlobalSection(profileName string, messageTag string, socketPath string, gpsPipePath string, forceLeapfile bool) {
	conf.profileName = profileName
	conf.setOption(GlobalSectionName, "message_tag", messageTag, true)
	if socketPath != "" {
		conf.setOption(GlobalSectionName, "uds_address", socketPath, true)
	}
	if gnssSerialPort, ok := conf.getOption(GlobalSectionName, "ts2phc.nmea_serialport"); ok {
		conf.gnssSerialPort = strings.TrimSpace(gnssSerialPort)
		conf.setOption(GlobalSectionName, "ts2phc.nmea_serialport", gpsPipePath, true)
	}
	if conf.leapFileEnabled || forceLeapfile {
		conf.setOption(GlobalSectionName, "leapfile", fmt.Sprintf("%s/%s", config.DefaultLeapConfigPath, os.Getenv("NODE_NAME")), true)
	}
}

// AddInterfaceSection adds interface to Ptp4lConf
func (conf *Ptp4lConf) AddInterfaceSection(iface string) {
	ifaceSectionName := fmt.Sprintf("[%s]", iface)
	conf.setOption(ifaceSectionName, "", "", false)
}

// RenderPtp4lConf outputs ptp4l config as string
func (conf *Ptp4lConf) RenderPtp4lConf() (configOut string, ifaces config.IFaces) {
	configOut = fmt.Sprintf("#profile: %s\n", conf.profileName)
	var nmeaSource event.EventSource

	for _, section := range conf.sections {
		configOut = fmt.Sprintf("%s\n%s", configOut, section.sectionName)

		if section.sectionName == NmeaSectionName {
			if source, ok := conf.getOption(section.sectionName, "ts2phc.master"); ok {
				nmeaSource = getSource(source)
			}
		}
		if section.sectionName != GlobalSectionName && section.sectionName != NmeaSectionName && section.sectionName != UnicastSectionName {
			i := section.sectionName
			i = strings.ReplaceAll(i, "[", "")
			i = strings.ReplaceAll(i, "]", "")
			iface := config.Iface{Name: i}
			if source, ok := conf.getOption(section.sectionName, "ts2phc.master"); ok {
				iface.Source = getSource(source)
			} else {
				iface.Source = nmeaSource
			}
			if masterOnly, ok := conf.getOption(section.sectionName, "masterOnly"); ok {
				iface.IsMaster, _ = strconv.ParseBool(strings.TrimSpace(masterOnly))
			}
			ifaces = append(ifaces, config.Iface{
				Name:     iface.Name,
				Source:   iface.Source,
				IsMaster: iface.IsMaster,
				PhcId:    iface.PhcId,
			})
		}
		for _, option := range section.options {
			k := option.key
			v := option.value
			configOut = fmt.Sprintf("%s\n%s %s", configOut, k, v)
		}
	}
	return configOut, ifaces
}

// RenderSyncE4lConf outputs synce4l config as string
func (conf *Ptp4lConf) RenderSyncE4lConf(ptpSettings map[string]string) (configOut string, relations *synce.Relations) {
	configOut = fmt.Sprintf("#profile: %s\n", conf.profileName)
	relations = conf.extractSynceRelations()
	relations.AddClockIds(ptpSettings)
	deviceIdx := 0

	for _, section := range conf.sections {
		configOut = fmt.Sprintf("%s\n%s", configOut, section.sectionName)
		if strings.HasPrefix(section.sectionName, "[<") {
			if _, found := conf.getOption(section.sectionName, "clock_id"); !found {
				conf.setOption(section.sectionName, "clock_id", relations.Devices[deviceIdx].ClockId, true)
				deviceIdx++
			}
		}
		for _, option := range section.options {
			k := option.key
			v := option.value
			configOut = fmt.Sprintf("%s\n%s %s", configOut, k, v)
		}
	}
	return
}

// AddFlagsForMonitor updates ptp4l config options used for monitoring.
func (conf *Ptp4lConf) AddFlagsForMonitor(configOpts *string, stdoutToSocket bool) {
	if configOpts == nil {
		return
	}
	if !strings.Contains(*configOpts, "-m") {
		glog.Info("adding -m to print messages to stdout for ptp4l to use prometheus exporter")
		*configOpts = fmt.Sprintf("%s -m", *configOpts)
	}

	if !strings.Contains(*configOpts, "--summary_interval") {
		_, exist := conf.getOption(GlobalSectionName, "summary_interval")
		if !exist {
			conf.setOption(GlobalSectionName, "summary_interval", "1", true)
		}
	}

	// stdoutToSocket is for sidecar to consume events, -u will not generate logs with offset and clock state.
	if stdoutToSocket && strings.Contains(*configOpts, "-u") {
		glog.Error("-u option will not generate clock state events,  remove -u option")
	} else if !stdoutToSocket && !strings.Contains(*configOpts, "-u") {
		glog.Info("adding -u 1 to print summary messages to stdout for phc2sys to use prometheus exporter")
		*configOpts = fmt.Sprintf("%s -u 1", *configOpts)
	}
}

// ExtractUpstreamPortsFromProfile extracts upstream ports (interfaces with masterOnly=0) from a PTP profile.
func ExtractUpstreamPortsFromProfile(ptpProfile *ptpv1.PtpProfile) []string {
	if ptpProfile == nil || ptpProfile.Ptp4lConf == nil {
		return nil
	}

	conf := &Ptp4lConf{}
	if err := conf.PopulatePtp4lConf(ptpProfile.Ptp4lConf); err != nil {
		glog.Warningf("Failed to parse ptp4l config while extracting upstream ports: %v", err)
		return nil
	}

	return conf.UpstreamPorts()
}

// UpstreamPorts returns interfaces with masterOnly=0 from the parsed configuration.
func (conf *Ptp4lConf) UpstreamPorts() []string {
	var upstreamPorts []string

	for _, section := range conf.sections {
		if section.sectionName == GlobalSectionName || section.sectionName == NmeaSectionName || section.sectionName == UnicastSectionName {
			continue
		}
		for _, option := range section.options {
			if option.key == "masterOnly" && strings.TrimSpace(option.value) == "0" {
				upstreamPorts = append(upstreamPorts, strings.Trim(section.sectionName, "[]"))
			}
		}
	}

	return upstreamPorts
}

// ClockType returns the derived clock type from the configuration.
func (conf *Ptp4lConf) ClockType() event.ClockType {
	return conf.clockType
}

// SetProfileName sets the profile name used when rendering.
func (conf *Ptp4lConf) SetProfileName(name string) {
	conf.profileName = name
}

// ProfileName returns the configured profile name.
func (conf *Ptp4lConf) ProfileName() string {
	return conf.profileName
}

// GNSSSerialPort returns the configured GNSS serial port (if any).
func (conf *Ptp4lConf) GNSSSerialPort() string {
	return conf.gnssSerialPort
}

// SetGNSSSerialPort sets the GNSS serial port path.
func (conf *Ptp4lConf) SetGNSSSerialPort(port string) {
	conf.gnssSerialPort = port
}

// GetOption returns an option value for a section.
func (conf *Ptp4lConf) GetOption(sectionName string, key string) (string, bool) {
	return conf.getOption(sectionName, key)
}

// SetOption sets or appends an option to a section.
func (conf *Ptp4lConf) SetOption(sectionName string, key string, value string, overwrite bool) {
	conf.setOption(sectionName, key, value, overwrite)
}

func (conf *Ptp4lConf) getOption(sectionName string, key string) (string, bool) {
	for _, section := range conf.sections {
		if section.sectionName == sectionName {
			for _, option := range section.options {
				if option.key == key {
					return option.value, true
				}
			}
		}
	}

	return "", false
}

func (conf *Ptp4lConf) setOption(sectionName string, key string, value string, overwrite bool) {
	var updatedSection ptp4lConfSection
	index := -1
	for i, section := range conf.sections {
		if section.sectionName == sectionName {
			updatedSection = section
			index = i
		}
	}
	if index < 0 {
		newSectionOptions := make([]ptp4lConfOption, 0)
		updatedSection = ptp4lConfSection{options: newSectionOptions, sectionName: sectionName}
		index = len(conf.sections)
		conf.sections = append(conf.sections, updatedSection)
	}

	// Stop now if initializing section without option
	if key == "" {
		return
	}
	found := false
	if overwrite {
		for i := range updatedSection.options {
			if updatedSection.options[i].key == key {
				updatedSection.options[i] = ptp4lConfOption{key: key, value: value}
				found = true
			}
		}
	}
	// Append unless already overwrote it.
	if !found {
		updatedSection.options = append(updatedSection.options, ptp4lConfOption{key: key, value: value})
	}

	// Update section in conf
	conf.sections[index] = updatedSection
}

func (conf *Ptp4lConf) extractSynceRelations() *synce.Relations {
	var err error
	r := &synce.Relations{
		Devices: []*synce.Config{},
	}

	ifaces := []string{}
	re, _ := regexp.Compile(`[{}<>\[\] ]+`)
	synceRelationInfo := synce.Config{}

	var extendedTlv, networkOption int
	for _, section := range conf.sections {
		sectionName := section.sectionName
		if strings.HasPrefix(sectionName, "[<") {
			if synceRelationInfo.Name != "" {
				if len(ifaces) > 0 {
					synceRelationInfo.Ifaces = ifaces
				}
				r.AddDeviceConfig(synceRelationInfo)
			}
			synceRelationInfo = synce.Config{
				Name:           "",
				Ifaces:         nil,
				ClockId:        "",
				NetworkOption:  synce.SYNCE_NETWORK_OPT_1,
				ExtendedTlv:    synce.ExtendedTLV_DISABLED,
				ExternalSource: "",
				LastQLState:    make(map[string]*synce.QualityLevelInfo),
				LastClockState: "",
			}

			synceRelationInfo.Name = re.ReplaceAllString(sectionName, "")
			if networkOptionStr, ok := conf.getOption(sectionName, "network_option"); ok {
				if networkOption, err = strconv.Atoi(strings.TrimSpace(networkOptionStr)); err != nil {
					glog.Errorf("error parsing `network_option`, setting network_option to default 1 : %s", err)
					networkOption = synce.SYNCE_NETWORK_OPT_1
				}
				synceRelationInfo.NetworkOption = networkOption
			}
			if extendedTlvStr, ok := conf.getOption(sectionName, "extended_tlv"); ok {
				if extendedTlv, err = strconv.Atoi(strings.TrimSpace(extendedTlvStr)); err != nil {
					glog.Errorf("error parsing `extended_tlv`, setting extended_tlv to default 0 : %s", err)
					extendedTlv = synce.ExtendedTLV_DISABLED
				}
				synceRelationInfo.ExtendedTlv = extendedTlv
			}
			if externalSource, ok := conf.getOption(sectionName, "external_source"); ok {
				synceRelationInfo.ExternalSource = re.ReplaceAllString(sectionName, "")
				if externalSource == "1" {
					synceRelationInfo.ExternalSource = re.ReplaceAllString(sectionName, "")
				}
			}
			if clockID, ok := conf.getOption(sectionName, "clock_id"); ok {
				synceRelationInfo.ClockId = clockID
			} else {
				synceRelationInfo.ClockId = re.ReplaceAllString(sectionName, "")
			}
		} else if strings.HasPrefix(sectionName, "[") && sectionName != GlobalSectionName {
			iface := re.ReplaceAllString(sectionName, "")
			ifaces = append(ifaces, iface)
		}
	}
	if len(ifaces) > 0 {
		synceRelationInfo.Ifaces = ifaces
	}
	if synceRelationInfo.Name != "" {
		r.AddDeviceConfig(synceRelationInfo)
	}
	return r
}

func getSource(isTs2phcMaster string) event.EventSource {
	if ts2phcMaster, err := strconv.ParseBool(strings.TrimSpace(isTs2phcMaster)); err == nil {
		if ts2phcMaster {
			return event.GNSS
		}
	}
	return event.PPS
}
