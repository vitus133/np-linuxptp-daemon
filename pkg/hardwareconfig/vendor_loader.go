package hardwareconfig

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/golang/glog"
	"sigs.k8s.io/yaml"
)

//TODO: fix the CRD in the opeerator to replace hardwarePlugin by hardwareSpecificDefinitions

// HardwareDefaults is the YAML-backed spec defining static defaults/options for specific hardware.
type HardwareDefaults struct {
	// PinDefaults maps board labels to default priorities/states for EEC/PPS
	PinDefaults map[string]*PinDefault `json:"pinDefaults,omitempty"`

	// ConnectorCommands defines commands to enable connectors as inputs, outputs or disable them
	ConnectorCommands *ConnectorCommands `json:"connectorCommands,omitempty"`

	// InternalDelays defines connector<->pin internal delays for this hardware model
	InternalDelays *InternalDelays `json:"internalDelays,omitempty"`
}

// PinDefault represents default pin configuration settings
type PinDefault struct {
	EEC *PinDefaultEntry `json:"eec,omitempty"`
	PPS *PinDefaultEntry `json:"pps,omitempty"`
}

// PinDefaultEntry represents individual pin default settings for EEC or PPS
type PinDefaultEntry struct {
	Priority *int64 `json:"priority,omitempty"`
	State    string `json:"state,omitempty"`
	Comment  string `json:"comment,omitempty"`
}

// ConnectorCommands groups actions per mode for device connectors
type ConnectorCommands struct {
	Outputs map[string]ConnectorAction `json:"outputs,omitempty"`
	Inputs  map[string]ConnectorAction `json:"inputs,omitempty"`
	Disable map[string]ConnectorAction `json:"disable,omitempty"`
}

// ConnectorAction is a list of low-level commands to execute for a connector
type ConnectorAction struct {
	Commands []ConnectorCommand `json:"commands"`
}

// ConnectorCommand represents a low-level action. Currently only FSWrite (sysfs write) is supported.
type ConnectorCommand struct {
	Type        string `json:"type"`
	Path        string `json:"path"`
	Value       string `json:"value"`
	Description string `json:"description,omitempty"`
}

// InternalDelays mirrors the structure from legacy addons for connector/pin delays.
type InternalDelays struct {
	PartType        string         `json:"partType"`
	ExternalInputs  []InternalLink `json:"externalInputs"`
	ExternalOutputs []InternalLink `json:"externalOutputs"`
	GnssInput       InternalLink   `json:"gnssInput"`
}

// InternalLink represents internal delay configuration between connectors and pins
type InternalLink struct {
	Connector string `json:"connector"`
	Pin       string `json:"pin"`
	DelayPs   int32  `json:"delayPs"`
}

// LoadHardwareDefaults loads defaults for a given hardware definition path (hwDefPath).
// Resolution priority:
//  1. Repository file: pkg/hardwareconfig/hardware-vendor/<hwDefPath>/defaults.yaml
//  2. Runtime file: /etc/linuxptp/hardware-vendor/<hwDefPath>/defaults.yaml
//  3. ConfigMap reference: if hwDefPath starts with "configmap:", read from
//     <CM_BASE>/<name>/defaults.yaml where CM_BASE defaults to /etc/configmaps
func LoadHardwareDefaults(hwDefPath string) (*HardwareDefaults, error) {
	if hwDefPath == "" {
		return nil, nil
	}

	if absRepoPath := repoDefaultsPath(hwDefPath); absRepoPath != "" {
		glog.Infof("Hardware defaults: expecting repo absolute path=%s", absRepoPath)
		if dir := filepath.Dir(absRepoPath); dir != "" {
			entries, err := os.ReadDir(dir)
			if err != nil {
				glog.Infof("Hardware defaults: failed to read dir %s: %v", dir, err)
			} else {
				var names []string
				for _, e := range entries {
					names = append(names, e.Name())
				}
				glog.Infof("Hardware defaults: dir %s entries=%v", dir, names)
			}
		}
		if b, err := os.ReadFile(absRepoPath); err == nil {
			glog.Infof("Hardware defaults: using repo path %s", absRepoPath)
			glog.Infof("Hardware defaults: raw YAML from %s:\n%s", absRepoPath, string(b))
			return decodeHardwareDefaults(absRepoPath, b)
		}
		glog.Infof("Hardware defaults: repo path %s not found", absRepoPath)
	}

	repoPath := filepath.Join("pkg", "hardwareconfig", "hardware-vendor", hwDefPath, "defaults.yaml")
	glog.Infof("Hardware defaults: expecting repo relative path=%s", repoPath)
	if dir := filepath.Dir(repoPath); dir != "" {
		entries, err := os.ReadDir(dir)
		if err != nil {
			glog.Infof("Hardware defaults: failed to read dir %s: %v", dir, err)
		} else {
			var names []string
			for _, e := range entries {
				names = append(names, e.Name())
			}
			glog.Infof("Hardware defaults: dir %s entries=%v", dir, names)
		}
	}
	if b, err := os.ReadFile(repoPath); err == nil {
		glog.Infof("Hardware defaults: using repo-relative path %s", repoPath)
		glog.Infof("Hardware defaults: raw YAML from %s:\n%s", repoPath, string(b))
		return decodeHardwareDefaults(repoPath, b)
	}
	glog.Infof("Hardware defaults: repo-relative path %s not found", repoPath)

	runtimeBaseEnv := os.Getenv("LINUXPTP_HW_VENDOR_BASE")
	runtimeBases := []string{}
	if runtimeBaseEnv != "" {
		runtimeBases = append(runtimeBases, runtimeBaseEnv)
	} else {
		runtimeBases = append(runtimeBases, "/etc/linuxptp/hardware-vendor")
	}
	runtimeBases = append(runtimeBases, "/usr/local/bin/hardware-vendor")
	if execPath, err := os.Executable(); err == nil {
		execDir := filepath.Dir(execPath)
		runtimeBases = append(runtimeBases, filepath.Join(execDir, "hardware-vendor"))
	} else {
		glog.Infof("Hardware defaults: failed to resolve executable path: %v", err)
	}
	for _, base := range runtimeBases {
		runtimePath := filepath.Join(base, hwDefPath, "defaults.yaml")
		glog.Infof("Hardware defaults: expecting runtime path=%s", runtimePath)
		if dir := filepath.Dir(runtimePath); dir != "" {
			entries, err := os.ReadDir(dir)
			if err != nil {
				glog.Infof("Hardware defaults: failed to read dir %s: %v", dir, err)
			} else {
				var names []string
				for _, e := range entries {
					names = append(names, e.Name())
				}
				glog.Infof("Hardware defaults: dir %s entries=%v", dir, names)
			}
		}
		if b, err := os.ReadFile(runtimePath); err == nil {
			glog.Infof("Hardware defaults: using runtime path %s", runtimePath)
			glog.Infof("Hardware defaults: raw YAML from %s:\n%s", runtimePath, string(b))
			return decodeHardwareDefaults(runtimePath, b)
		}
		glog.Infof("Hardware defaults: runtime path %s not found", runtimePath)
	}

	if strings.HasPrefix(hwDefPath, "configmap:") {
		if configMapResolver == nil {
			glog.Infof("Hardware defaults requested from configmap but no resolver is set: %s", hwDefPath)
			return nil, nil
		}

		ns, name, key := parseConfigMapRef(hwDefPath)
		glog.Infof("Hardware defaults: resolving configmap %s/%s key=%s", ns, name, key)
		data, err := configMapResolver(context.TODO(), ns, name)
		if err != nil {
			return nil, fmt.Errorf("get configmap %s/%s: %w", ns, name, err)
		}
		if data == nil {
			glog.Infof("Hardware defaults: configmap %s/%s returned no data", ns, name)
			return nil, nil
		}
		content, ok := data[key]
		if !ok {
			glog.Infof("ConfigMap %s/%s does not contain key %s", ns, name, key)
			return nil, nil
		}
		return decodeHardwareDefaults(fmt.Sprintf("cm:%s/%s:%s", ns, name, key), []byte(content))
	}

	glog.Infof("Hardware defaults: no defaults found for %s", hwDefPath)
	return nil, nil
}

// repoDefaultsPath returns an absolute path to the defaults.yaml next to this package, independent of CWD
func repoDefaultsPath(hwDefPath string) string {
	_, file, _, ok := runtime.Caller(0)
	if !ok || file == "" {
		return ""
	}
	glog.Infof("repoDefaultsPath: %s", file)
	base := filepath.Dir(file)
	return filepath.Join(base, "hardware-vendor", hwDefPath, "defaults.yaml")
}

func decodeHardwareDefaults(path string, data []byte) (*HardwareDefaults, error) {
	var hd HardwareDefaults
	if err := yaml.Unmarshal(data, &hd); err != nil {
		return nil, fmt.Errorf("unmarshal %s: %w", path, err)
	}
	return &hd, nil
}

// --- ConfigMap resolver injection ---

// ConfigMapResolver fetches configmap data[key]=content
type ConfigMapResolver func(ctx context.Context, namespace, name string) (map[string]string, error)

var configMapResolver ConfigMapResolver

// SetConfigMapResolver injects a resolver used to fetch defaults from a ConfigMap via API
func SetConfigMapResolver(r ConfigMapResolver) {
	configMapResolver = r
}

// parseConfigMapRef accepts formats:
//
//	configmap:ns/name
//	configmap:ns/name:key
//
// if key is omitted, defaults to "defaults.yaml"
func parseConfigMapRef(ref string) (namespace, name, key string) {
	rest := strings.TrimPrefix(ref, "configmap:")
	key = "defaults.yaml"
	// split by ':' to extract optional key
	base := rest
	if i := strings.Index(rest, ":"); i >= 0 {
		base = rest[:i]
		key = rest[i+1:]
	}
	// base must be ns/name
	if j := strings.Index(base, "/"); j >= 0 {
		namespace = base[:j]
		name = base[j+1:]
	} else {
		// no namespace specified; use injected default namespace (from daemon.PtpNamespace)
		namespace = defaultNamespaceOr("default")
		name = base
	}
	return
}

// defaultNamespace is injected by the daemon via SetDefaultNamespace
var defaultNamespace string

// SetDefaultNamespace sets the namespace used when a ConfigMap ref omits it
func SetDefaultNamespace(ns string) { defaultNamespace = ns }

func defaultNamespaceOr(fallback string) string {
	if defaultNamespace != "" {
		return defaultNamespace
	}
	return fallback
}
