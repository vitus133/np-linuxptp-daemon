package phcfirststep

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	ptpv1 "github.com/k8snetworkplumbingwg/ptp-operator/api/v1"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

// TestNew covers successful registration under the plugin name and rejection of another name.
func TestNew(t *testing.T) {
	got, data := New(pluginName)
	if got == nil || data == nil || got.Name != pluginName || got.OnPTPConfigChange == nil {
		t.Fatalf("unexpected plugin registration: plugin=%+v data=%v", got, data)
	}
	if got, data := New("other"); got != nil || data != nil {
		t.Fatalf("expected wrong plugin name to be rejected, got plugin=%v data=%v", got, data)
	}
}

// TestOnPTPConfigChangeOnlyWhenSelected verifies an unselected profile returns without PHC discovery.
func TestOnPTPConfigChangeOnlyWhenSelected(t *testing.T) {
	old := phcIDForIface
	phcIDForIface = func(string) string {
		t.Fatal("unselected plugin must not discover a PHC")
		return ""
	}
	t.Cleanup(func() { phcIDForIface = old })

	conf := "[eth0]\nmasterOnly 0\n"
	profile := &ptpv1.PtpProfile{Ptp4lConf: &conf}
	if err := onPTPConfigChange(nil, profile); err != nil {
		t.Fatalf("unselected plugin returned an error: %v", err)
	}
}

// TestTimeReceiverInterfaces covers selection of masterOnly 0 ports, exclusion of non-port sections,
// and handling of a nil profile.
func TestTimeReceiverInterfaces(t *testing.T) {
	conf := "[global]\nmasterOnly 0\n" +
		"[nmea]\nmasterOnly 0\n" +
		"[unicast_master_table]\nmasterOnly 0\n" +
		"[eth0]\nmasterOnly 0\n" +
		"[eth1]\nmasterOnly 0\n" +
		"[eth2]\nmasterOnly 1\n"
	profile := &ptpv1.PtpProfile{Ptp4lConf: &conf}
	got := timeReceiverInterfaces(profile)
	if want := []string{"eth0", "eth1"}; !equalStrings(got, want) {
		t.Fatalf("timeReceiverInterfaces() = %v, want %v", got, want)
	}
	if got := timeReceiverInterfaces(nil); len(got) != 0 {
		t.Fatalf("nil profile returned interfaces %v", got)
	}
}

// TestValidateE825PHC covers direct and aliased device matches, missing e825 configuration,
// and e825 devices exposing a different PHC.
func TestValidateE825PHC(t *testing.T) {
	old := phcIDForIface
	t.Cleanup(func() { phcIDForIface = old })
	tests := []struct {
		name    string
		profile *ptpv1.PtpProfile
		phcs    map[string]string
		wantErr bool
	}{
		{
			name:    "e825 device exposes the TR PHC",
			profile: selectedProfile(t, "[eth0]\nmasterOnly 0\n", "", []string{"eth0"}),
			phcs:    map[string]string{"eth0": "/dev/ptp0"},
		},
		{
			name:    "different interface name exposes the same PHC",
			profile: selectedProfile(t, "[eno8303]\nmasterOnly 0\n", "", []string{"eno8703"}),
			phcs:    map[string]string{"eno8303": "/dev/ptp0", "eno8703": "/dev/ptp0"},
		},
		{
			name:    "missing e825 configuration",
			profile: profileWithPlugins("[eth0]\nmasterOnly 0\n", map[string]*apiextensions.JSON{pluginName: {Raw: []byte(`{}`)}}),
			wantErr: true,
		},
		{
			name:    "e825 devices expose another PHC",
			profile: selectedProfile(t, "[eth0]\nmasterOnly 0\n", "", []string{"eth1"}),
			phcs:    map[string]string{"eth0": "/dev/ptp0", "eth1": "/dev/ptp1"},
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			phcIDForIface = func(iface string) string { return test.phcs[iface] }
			err := validateE825PHC(test.profile, "/dev/ptp0")
			if (err != nil) != test.wantErr {
				t.Fatalf("validateE825PHC() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

// TestSharedPHC covers one or multiple interfaces on one PHC, unresolved PHCs, and mixed PHCs.
func TestSharedPHC(t *testing.T) {
	old := phcIDForIface
	t.Cleanup(func() { phcIDForIface = old })
	tests := []struct {
		name       string
		devices    map[string]string
		interfaces []string
		want       string
		wantErr    bool
	}{
		{name: "one interface", devices: map[string]string{"eth0": "/dev/ptp0"}, interfaces: []string{"eth0"}, want: "/dev/ptp0"},
		{name: "multiple interfaces share PHC", devices: map[string]string{"eth0": "/dev/ptp0", "eth1": "/dev/ptp0"}, interfaces: []string{"eth0", "eth1"}, want: "/dev/ptp0"},
		{name: "unresolved PHC", devices: map[string]string{"eth0": ""}, interfaces: []string{"eth0"}, wantErr: true},
		{name: "different PHCs", devices: map[string]string{"eth0": "/dev/ptp0", "eth1": "/dev/ptp1"}, interfaces: []string{"eth0", "eth1"}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			phcIDForIface = func(iface string) string { return test.devices[iface] }
			got, err := sharedPHC(test.interfaces)
			if (err != nil) != test.wantErr {
				t.Fatalf("sharedPHC() error = %v, wantErr %v", err, test.wantErr)
			}
			if got != test.want {
				t.Fatalf("sharedPHC() = %q, want %q", got, test.want)
			}
		})
	}
}

// TestMeasurementTimeout covers unset, valid, malformed, and negative timeout options.
func TestMeasurementTimeout(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    time.Duration
		wantErr bool
	}{
		{name: "unset", raw: `{}`, want: 0},
		{name: "configured", raw: `{"timeout":"15s"}`, want: 15 * time.Second},
		{name: "invalid", raw: `{"timeout":"bad"}`, wantErr: true},
		{name: "negative", raw: `{"timeout":"-1s"}`, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profile := &ptpv1.PtpProfile{Plugins: map[string]*apiextensions.JSON{
				pluginName: {Raw: []byte(test.raw)},
			}}
			got, err := measurementTimeout(profile)
			if (err != nil) != test.wantErr {
				t.Fatalf("measurementTimeout() error = %v, wantErr %v", err, test.wantErr)
			}
			if got != test.want {
				t.Fatalf("measurementTimeout() = %s, want %s", got, test.want)
			}
		})
	}
}

// TestParseSampleRequiresNonZeroPathDelay accepts valid offsets and rejects zero-delay or unrelated lines.
func TestParseSampleRequiresNonZeroPathDelay(t *testing.T) {
	tests := []struct {
		line       string
		wantOffset int64
		wantValid  bool
	}{
		{line: "ptp4l[1.0]: master offset 0 s0 freq +1 path delay 80", wantValid: true},
		{line: "ptp4l[1.0]: master offset -19 s0 freq +1 path delay 83", wantOffset: -19, wantValid: true},
		{line: "ptp4l[1.0]: master offset 10 s0 freq +1 path delay 0"},
		{line: "ptp4l[1.0]: master offset 10 s0 freq +1 path delay +0"},
		{line: "ptp4l[1.0]: unrelated status line"},
	}
	for _, test := range tests {
		got, valid := parseSample(test.line)
		if valid != test.wantValid || valid && got != test.wantOffset {
			t.Errorf("parseSample(%q) = (%d, %v), want (%d, %v)", test.line, got, valid, test.wantOffset, test.wantValid)
		}
	}
}

// TestRenderMeasurementConfig verifies global options and selected TR sections are retained while other ports are omitted.
func TestRenderMeasurementConfig(t *testing.T) {
	conf := "[global]\ndomainNumber 24\nmasterOnly 0\ndataset_comparison G.8275.x\n" +
		"[eth0]\nmasterOnly 0\ntransportSpecific 0x1\n" +
		"[eth1]\nmasterOnly 0\n" +
		"[eth2]\nmasterOnly 1\n"
	got, err := renderMeasurementConfig(&ptpv1.PtpProfile{Ptp4lConf: &conf}, []string{"eth0", "eth1"})
	if err != nil {
		t.Fatalf("renderMeasurementConfig() error: %v", err)
	}
	for _, want := range []string{"domainNumber 24", "dataset_comparison G.8275.x", "[eth0]", "[eth1]", "masterOnly 0", "transportSpecific 0x1"} {
		if !strings.Contains(got, want) {
			t.Errorf("rendered config missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "[eth2]") || strings.Count(got, "masterOnly 0") != 2 {
		t.Errorf("rendered config included an unselected interface or omitted a TR section:\n%s", got)
	}
}

func TestSetPHCTimeNegativeValue(t *testing.T) {
	argsFile := filepath.Join(t.TempDir(), "phc-ctl-args")
	phcCtl := "#!/bin/sh\n" +
		"if [ \"$2\" != \"--\" ]; then echo 'missing phc_ctl command separator' >&2; exit 2; fi\n" +
		"printf '%s\\n' \"$@\" > \"$PHC_CTL_ARGS\"\n" +
		"[ \"$3\" = set ] && [ \"$4\" = -515051308.470896042 ]\n"
	installFakeCommands(t, "", phcCtl)
	t.Setenv("PHC_CTL_ARGS", argsFile)

	if err := setPHCTime(context.Background(), "/dev/ptp0", -515051307529103958); err != nil {
		t.Fatalf("setPHCTime() error: %v", err)
	}
	got, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("read phc_ctl arguments: %v", err)
	}
	if want := "/dev/ptp0\n--\nset\n-515051308.470896042\n"; string(got) != want {
		t.Fatalf("phc_ctl arguments = %q, want %q", got, want)
	}
}

func TestReadPHCTimeNegativeValue(t *testing.T) {
	phcCtl := "#!/bin/sh\n" +
		"[ \"$2\" = -- ] && [ \"$3\" = get ] || exit 2\n" +
		"echo 'clock time is -515051308.470896042'\n"
	installFakeCommands(t, "", phcCtl)

	got, err := readPHCTime(context.Background(), "/dev/ptp0")
	if err != nil {
		t.Fatalf("readPHCTime() error: %v", err)
	}
	if want := int64(-515051307529103958); got != want {
		t.Fatalf("readPHCTime() = %d, want %d", got, want)
	}
}

// TestOnPTPConfigChangeValidationDoesNotRunCommands covers missing TR ports, e825 mismatch, unresolved PHC,
// and multiple PHCs, confirming validation fails before external commands run.
func TestOnPTPConfigChangeValidationDoesNotRunCommands(t *testing.T) {
	installFakeCommands(t, "#!/bin/sh\ntouch \"$COMMAND_MARKER\"\nexit 1\n", "#!/bin/sh\ntouch \"$COMMAND_MARKER\"\nexit 1\n")
	marker := filepath.Join(t.TempDir(), "command-ran")
	t.Setenv("COMMAND_MARKER", marker)
	old := phcIDForIface
	t.Cleanup(func() { phcIDForIface = old })
	tests := []struct {
		name     string
		profile  *ptpv1.PtpProfile
		resolver func(string) string
		wantErr  bool
	}{
		{
			name:    "no TR interfaces",
			profile: selectedProfile(t, "[eth0]\nmasterOnly 1\n", "", []string{"eth0"}),
			wantErr: true,
		},
		{
			name:    "e825 device exposes another PHC",
			profile: selectedProfile(t, "[eth0]\nmasterOnly 0\n", "", []string{"eth1"}),
			resolver: func(iface string) string {
				if iface == "eth0" {
					return "/dev/ptp0"
				}
				return "/dev/ptp1"
			},
			wantErr: true,
		},
		{
			name:     "unresolved PHC",
			profile:  selectedProfile(t, "[eth0]\nmasterOnly 0\n", "", []string{"eth0"}),
			resolver: func(string) string { return "" },
			wantErr:  true,
		},
		{
			name:    "interfaces on different PHCs",
			profile: selectedProfile(t, "[eth0]\nmasterOnly 0\n[eth1]\nmasterOnly 0\n", "", []string{"eth0", "eth1"}),
			resolver: func(iface string) string {
				if iface == "eth0" {
					return "/dev/ptp0"
				}
				return "/dev/ptp1"
			},
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			phcIDForIface = test.resolver
			if test.resolver == nil {
				phcIDForIface = func(string) string { return "/dev/ptp0" }
			}
			err := onPTPConfigChange(nil, test.profile)
			if (err != nil) != test.wantErr {
				t.Fatalf("onPTPConfigChange() error = %v, wantErr %v", err, test.wantErr)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatalf("external command ran before input validation completed; marker stat error=%v", err)
			}
		})
	}
}

// TestOnPTPConfigChangeMeasuresAndSetsSharedPHC covers zero-delay filtering, first-16 averaging,
// corrected-time calculation, shared-PHC selection, and waiting for phc_ctl set to finish.
func TestOnPTPConfigChangeMeasuresAndSetsSharedPHC(t *testing.T) {
	var samples strings.Builder
	samples.WriteString("printf 'ptp4l: master offset 999 s0 freq +0 path delay 0\\n'\n")
	samples.WriteString("i=1\nwhile [ \"$i\" -le 16 ]; do\n")
	samples.WriteString("  printf 'ptp4l: master offset %s s0 freq +0 path delay 80\\n' \"$i\"\n")
	samples.WriteString("  i=$((i + 1))\ndone\n")
	samples.WriteString("printf 'ptp4l: master offset 100000 s0 freq +0 path delay 80\\n'\n")
	phcCtl := "#!/bin/sh\n[ \"$2\" = -- ] || exit 2\ncase \"$3\" in\n" +
		"get) echo get >> \"$PHC_CTL_LOG\"; echo 'clock time is 100.000000000' ;;\n" +
		"set) echo \"set $4\" >> \"$PHC_CTL_LOG\"; sleep 0.1; touch \"$PHC_SET_COMPLETE\" ;;\n" +
		"*) exit 2 ;;\nesac\n"
	installFakeCommands(t, "#!/bin/sh\n"+samples.String(), phcCtl)
	log := filepath.Join(t.TempDir(), "phc-ctl.log")
	complete := filepath.Join(t.TempDir(), "set-complete")
	t.Setenv("PHC_CTL_LOG", log)
	t.Setenv("PHC_SET_COMPLETE", complete)

	old := phcIDForIface
	phcIDForIface = func(string) string { return "/dev/ptp0" }
	t.Cleanup(func() { phcIDForIface = old })
	conf := "[global]\ndomainNumber 24\n[eno8303]\nmasterOnly 0\n[eno8304]\nmasterOnly 0\n"
	profile := selectedProfile(t, conf, "", []string{"eno8703"})
	phcIDForIface = func(iface string) string {
		switch iface {
		case "eno8303", "eno8304", "eno8703":
			return "/dev/ptp0"
		default:
			return ""
		}
	}
	if err := onPTPConfigChange(nil, profile); err != nil {
		t.Fatalf("onPTPConfigChange() error: %v", err)
	}
	got, err := os.ReadFile(log)
	if err != nil {
		t.Fatalf("read PHC command log: %v", err)
	}
	if want := "get\nset 99.999999992\n"; string(got) != want {
		t.Fatalf("PHC commands = %q, want %q", got, want)
	}
	if _, err := os.Stat(complete); err != nil {
		t.Fatalf("callback returned before phc_ctl set completed: %v", err)
	}
}

// TestMeasureOffsetRequiresAllSamplesAndCleansUpOnTimeout covers unbounded waiting, early process exit,
// configured timeout, temporary-config removal, and measurement-process termination.
func TestMeasureOffsetRequiresAllSamplesAndCleansUpOnTimeout(t *testing.T) {
	t.Run("unset timeout waits for samples", func(t *testing.T) {
		var script strings.Builder
		script.WriteString("#!/bin/sh\nsleep 0.2\ni=1\nwhile [ \"$i\" -le 16 ]; do\n")
		script.WriteString("  printf 'master offset 4 s0 freq +0 path delay 10\\n'\n  i=$((i + 1))\ndone\n")
		installFakeCommands(t, script.String(), "")
		profile := selectedProfile(t, "[eth0]\nmasterOnly 0\n", "", []string{"eth0"})
		start := time.Now()
		got, err := measureOffset(context.Background(), profile, []string{"eth0"}, 0)
		if err != nil {
			t.Fatalf("measureOffset() error: %v", err)
		}
		if got != 4 {
			t.Fatalf("mean offset = %d, want 4", got)
		}
		if time.Since(start) < 150*time.Millisecond {
			t.Fatal("measurement returned before ptp4l produced valid samples")
		}
	})

	t.Run("process exits early", func(t *testing.T) {
		installFakeCommands(t, "#!/bin/sh\nprintf 'master offset 4 s0 freq +0 path delay 10\\n'\n", "")
		profile := selectedProfile(t, "[eth0]\nmasterOnly 0\n", "", []string{"eth0"})
		_, err := measureOffset(context.Background(), profile, []string{"eth0"}, 0)
		if err == nil || !strings.Contains(err.Error(), "1 of 16") {
			t.Fatalf("measureOffset() error = %v, want early-exit sample error", err)
		}
	})

	t.Run("configured timeout removes config and kills process", func(t *testing.T) {
		capture := filepath.Join(t.TempDir(), "config-path")
		pidFile := filepath.Join(t.TempDir(), "ptp4l-pid")
		ptp4l := "#!/bin/sh\nprintf '%s' \"$2\" > \"$PHC_CONFIG_CAPTURE\"\n" +
			"printf '%s' \"$$\" > \"$PHC_PID_FILE\"\nexec sleep 5\n"
		installFakeCommands(t, ptp4l, "")
		t.Setenv("PHC_CONFIG_CAPTURE", capture)
		t.Setenv("PHC_PID_FILE", pidFile)
		profile := selectedProfile(t, "[eth0]\nmasterOnly 0\n", "", []string{"eth0"})
		start := time.Now()
		_, err := measureOffset(context.Background(), profile, []string{"eth0"}, 500*time.Millisecond)
		if err == nil || !strings.Contains(err.Error(), "timed out") {
			t.Fatalf("measureOffset() error = %v, want timeout", err)
		}
		if time.Since(start) > 2*time.Second {
			t.Fatalf("configured measurement timeout took %s", time.Since(start))
		}
		configPathBytes, err := os.ReadFile(capture)
		if err != nil {
			t.Fatalf("read captured config path: %v", err)
		}
		if _, err := os.Stat(string(configPathBytes)); !os.IsNotExist(err) {
			t.Fatalf("temporary config still exists after timeout; stat error=%v", err)
		}
		pidBytes, err := os.ReadFile(pidFile)
		if err != nil {
			t.Fatalf("read ptp4l pid: %v", err)
		}
		var pid int
		if _, err := fmt.Sscan(string(pidBytes), &pid); err != nil {
			t.Fatalf("parse ptp4l pid: %v", err)
		}
		if err := syscall.Kill(pid, 0); err == nil {
			t.Fatalf("ptp4l process %d is still running after timeout", pid)
		}
	})
}

func TestMeasureOffsetDoesNotOverflowAveraging(t *testing.T) {
	ptp4l := "#!/bin/sh\n" +
		"i=0\nwhile [ \"$i\" -lt 16 ]; do\n" +
		"  printf 'master offset -1790873630319811923 s0 freq +1 path delay 10\\n'\n" +
		"  i=$((i + 1))\ndone\n"
	installFakeCommands(t, ptp4l, "")
	profile := selectedProfile(t, "[eth0]\nmasterOnly 0\n", "", []string{"eth0"})

	got, err := measureOffset(context.Background(), profile, []string{"eth0"}, 0)
	if err != nil {
		t.Fatalf("measureOffset() error: %v", err)
	}
	if want := int64(-1790873630319811923); got != want {
		t.Fatalf("mean offset = %d, want %d", got, want)
	}
}

// TestOnPTPConfigChangePHCCommandFailuresAndCompletion covers PHC get/set failures and success without read-back.
func TestOnPTPConfigChangePHCCommandFailuresAndCompletion(t *testing.T) {
	tests := []struct {
		name       string
		phcFailure string
		wantErr    bool
		wantLog    string
	}{
		{name: "get failure", phcFailure: "get", wantErr: true, wantLog: "get\n"},
		{name: "set failure", phcFailure: "set", wantErr: true, wantLog: "get\nset 99.999999992\n"},
		{name: "set success does not read back", wantLog: "get\nset 99.999999992\n"},
	}
	var samples strings.Builder
	samples.WriteString("i=1\nwhile [ \"$i\" -le 16 ]; do\n")
	samples.WriteString("  printf 'master offset 8 s0 freq +0 path delay 10\\n'\n  i=$((i + 1))\ndone\n")
	phcCtl := "#!/bin/sh\n[ \"$2\" = -- ] || exit 2\ncase \"$3\" in\n" +
		"get) echo get >> \"$PHC_CTL_LOG\"; if [ \"$PHC_FAIL\" = get ]; then exit 1; fi; echo 'clock time is 100.000000000' ;;\n" +
		"set) echo \"set $4\" >> \"$PHC_CTL_LOG\"; if [ \"$PHC_FAIL\" = set ]; then exit 1; fi ;;\nesac\n"
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			installFakeCommands(t, "#!/bin/sh\n"+samples.String(), phcCtl)
			log := filepath.Join(t.TempDir(), "phc-ctl.log")
			t.Setenv("PHC_CTL_LOG", log)
			t.Setenv("PHC_FAIL", test.phcFailure)
			old := phcIDForIface
			phcIDForIface = func(string) string { return "/dev/ptp0" }
			t.Cleanup(func() { phcIDForIface = old })
			profile := selectedProfile(t, "[eth0]\nmasterOnly 0\n", "", []string{"eth0"})
			err := onPTPConfigChange(nil, profile)
			if (err != nil) != test.wantErr {
				t.Fatalf("onPTPConfigChange() error = %v, wantErr %v", err, test.wantErr)
			}
			got, readErr := os.ReadFile(log)
			if readErr != nil {
				t.Fatalf("read PHC command log: %v", readErr)
			}
			if string(got) != test.wantLog {
				t.Fatalf("PHC commands = %q, want %q", got, test.wantLog)
			}
		})
	}
}

func selectedProfile(t *testing.T, ptp4lConf, timeout string, e825Devices []string) *ptpv1.PtpProfile {
	t.Helper()
	options := `{}`
	if timeout != "" {
		encoded, err := json.Marshal(pluginOptions{Timeout: timeout})
		if err != nil {
			t.Fatal(err)
		}
		options = string(encoded)
	}
	devices, err := json.Marshal(struct {
		Devices []string `json:"devices"`
	}{Devices: e825Devices})
	if err != nil {
		t.Fatal(err)
	}
	return profileWithPlugins(ptp4lConf, map[string]*apiextensions.JSON{
		pluginName: {Raw: []byte(options)},
		"e825":     {Raw: devices},
	})
}

func profileWithPlugins(ptp4lConf string, plugins map[string]*apiextensions.JSON) *ptpv1.PtpProfile {
	name := "test-profile"
	return &ptpv1.PtpProfile{Name: &name, Ptp4lConf: &ptp4lConf, Plugins: plugins}
}

func installFakeCommands(t *testing.T, ptp4lScript, phcCtlScript string) {
	t.Helper()
	dir := t.TempDir()
	for name, script := range map[string]string{"ptp4l": ptp4lScript, "phc_ctl": phcCtlScript} {
		if script == "" {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
