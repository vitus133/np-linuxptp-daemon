package intel

import (
	"encoding/json"
	"errors"
	"testing"

	dpll "github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/dpll-netlink"
	ptpv1 "github.com/k8snetworkplumbingwg/ptp-operator/api/v1"
	"github.com/stretchr/testify/assert"
)

const testE825ClockID = uint64(0x1234)

func testE825Pin(id uint32, boardLabel, packageLabel string, clockID uint64) *dpll.PinInfo {
	return &dpll.PinInfo{
		ID:              id,
		ClockID:         clockID,
		BoardLabel:      boardLabel,
		PackageLabel:    packageLabel,
		PhaseAdjustMin:  -30000,
		PhaseAdjustMax:  30000,
		PhaseAdjustGran: 100,
	}
}

func TestE825OptsAllDevicesIncludesPhaseAdjustmentDevices(t *testing.T) {
	t.Parallel()

	var opts E825Opts
	err := json.Unmarshal([]byte(`{"devices":["eno4"],"phaseAdjustments":{"eno5":{"REF0P":-8600},"eno6":{"OUT2P":-25000},"eno7":{}}}`), &opts)
	if !assert.NoError(t, err) {
		return
	}
	assert.ElementsMatch(t, []string{"eno4", "eno5", "eno6"}, opts.allDevices())
}

func TestResolveE825PhaseAdjustmentsLabels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		label     string
		pins      []*dpll.PinInfo
		wantPinID uint32
		wantErr   string
	}{
		{
			name:      "board label wins over package label",
			label:     "REF0P",
			pins:      []*dpll.PinInfo{testE825Pin(1, "REF0P", "PACKAGE-A", testE825ClockID), testE825Pin(2, "OTHER", "REF0P", testE825ClockID)},
			wantPinID: 1,
		},
		{
			name:      "package label fallback",
			label:     "PACKAGE-REF0P",
			pins:      []*dpll.PinInfo{testE825Pin(3, "REF0P", "PACKAGE-REF0P", testE825ClockID)},
			wantPinID: 3,
		},
		{
			name:    "ambiguous board label rejected",
			label:   "REF0P",
			pins:    []*dpll.PinInfo{testE825Pin(1, "REF0P", "A", testE825ClockID), testE825Pin(2, "REF0P", "B", testE825ClockID)},
			wantErr: "2 DPLL pins have board label",
		},
		{
			name:    "pin in another clock context is ignored",
			label:   "REF0P",
			pins:    []*dpll.PinInfo{testE825Pin(1, "REF0P", "PACKAGE-REF0P", testE825ClockID+1)},
			wantErr: "no DPLL pin has board or package label",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			profile := &ptpv1.PtpProfile{PtpSettings: map[string]string{"clockId[eno5]": "4660"}}
			opts := E825Opts{PhaseAdjustments: map[string]map[string]int64{"eno5": {tc.label: -8600}}}
			got, err := resolveE825PhaseAdjustments(profile, opts, tc.pins)
			if tc.wantErr != "" {
				if !assert.Error(t, err) {
					return
				}
				assert.ErrorContains(t, err, tc.wantErr)
				assert.Empty(t, got)
				return
			}
			if !assert.NoError(t, err) || !assert.Len(t, got, 1) {
				return
			}
			assert.Equal(t, tc.wantPinID, got[0].pinID)
			assert.Equal(t, int32(-8600), got[0].phaseAdjust)
		})
	}
}

func TestResolveE825PhaseAdjustmentsRejectsUnresolvedClockID(t *testing.T) {
	t.Parallel()

	profile := &ptpv1.PtpProfile{PtpSettings: map[string]string{"clockId[eno5]": "0"}}
	opts := E825Opts{PhaseAdjustments: map[string]map[string]int64{"eno5": {"REF0P": -8600}}}
	_, err := resolveE825PhaseAdjustments(profile, opts, []*dpll.PinInfo{testE825Pin(1, "REF0P", "PACKAGE-REF0P", 0)})
	if !assert.Error(t, err) {
		return
	}
	assert.ErrorContains(t, err, "unresolved DPLL clock ID")
}

func TestResolveE825PhaseAdjustmentsValidatesValues(t *testing.T) {
	t.Parallel()

	basePin := testE825Pin(1, "REF0P", "PACKAGE-REF0P", testE825ClockID)
	tests := []struct {
		name  string
		value int64
		pin   *dpll.PinInfo
		want  string
	}{
		{name: "below minimum", value: -30100, pin: basePin, want: "below pin minimum"},
		{name: "above maximum", value: 30100, pin: basePin, want: "above pin maximum"},
		{name: "off granularity", value: -8650, pin: basePin, want: "not aligned to pin granularity"},
		{name: "outside int32", value: 1 << 31, pin: basePin, want: "exceeds the DPLL phase-adjustment range"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			profile := &ptpv1.PtpProfile{PtpSettings: map[string]string{"clockId[eno5]": "4660"}}
			opts := E825Opts{PhaseAdjustments: map[string]map[string]int64{"eno5": {"REF0P": tc.value}}}
			got, err := resolveE825PhaseAdjustments(profile, opts, []*dpll.PinInfo{tc.pin})
			if !assert.Error(t, err) {
				return
			}
			assert.ErrorContains(t, err, tc.want)
			assert.Empty(t, got)
		})
	}
}

func TestResolveE825PhaseAdjustmentsRejectsDuplicateTargets(t *testing.T) {
	t.Parallel()

	profile := &ptpv1.PtpProfile{PtpSettings: map[string]string{"clockId[eno5]": "4660"}}
	opts := E825Opts{PhaseAdjustments: map[string]map[string]int64{
		"eno5": {"REF0P": -8600, "PACKAGE-REF0P": -8700},
	}}
	pins := []*dpll.PinInfo{testE825Pin(1, "REF0P", "PACKAGE-REF0P", testE825ClockID)}
	got, err := resolveE825PhaseAdjustments(profile, opts, pins)
	if !assert.Error(t, err) {
		return
	}
	assert.ErrorContains(t, err, "resolve to the same DPLL pin ID")
	assert.Empty(t, got)
}

type fakeE825PhaseAdjustmentWriter struct {
	adjustments []e825PhaseAdjustment
	err         error
}

func (w *fakeE825PhaseAdjustmentWriter) Apply(adjustments []e825PhaseAdjustment) error {
	w.adjustments = append(w.adjustments, adjustments...)
	return w.err
}

func TestE825ApplyPhaseAdjustments(t *testing.T) {
	t.Parallel()

	t.Run("no entries do not call writer", func(t *testing.T) {
		t.Parallel()
		writer := &fakeE825PhaseAdjustmentWriter{}
		data := E825PluginData{phaseAdjustmentWriter: writer}
		err := data.applyPhaseAdjustments(&ptpv1.PtpProfile{}, E825Opts{
			PhaseAdjustments: map[string]map[string]int64{"eno5": {}},
		})
		assert.NoError(t, err)
		assert.Empty(t, writer.adjustments)
	})

	t.Run("only configured values are sent unchanged", func(t *testing.T) {
		t.Parallel()
		writer := &fakeE825PhaseAdjustmentWriter{}
		data := E825PluginData{
			dpllPins:              []*dpll.PinInfo{testE825Pin(5, "OUT2P", "HPE-OUT2P", testE825ClockID)},
			phaseAdjustmentWriter: writer,
		}
		profile := &ptpv1.PtpProfile{PtpSettings: map[string]string{"clockId[eno5]": "4660"}}
		opts := E825Opts{PhaseAdjustments: map[string]map[string]int64{"eno5": {"HPE-OUT2P": -25000}}}
		err := data.applyPhaseAdjustments(profile, opts)
		if !assert.NoError(t, err) || !assert.Len(t, writer.adjustments, 1) {
			return
		}
		assert.Equal(t, "HPE-OUT2P", writer.adjustments[0].requested)
		assert.Equal(t, uint32(5), writer.adjustments[0].pinID)
		assert.Equal(t, int32(-25000), writer.adjustments[0].phaseAdjust)
	})

	t.Run("invalid later target prevents all writer calls", func(t *testing.T) {
		t.Parallel()
		writer := &fakeE825PhaseAdjustmentWriter{}
		data := E825PluginData{
			dpllPins:              []*dpll.PinInfo{testE825Pin(4, "A-VALID", "PACKAGE-A-VALID", testE825ClockID)},
			phaseAdjustmentWriter: writer,
		}
		profile := &ptpv1.PtpProfile{PtpSettings: map[string]string{"clockId[eno5]": "4660"}}
		opts := E825Opts{PhaseAdjustments: map[string]map[string]int64{"eno5": {
			"A-VALID": -25000, "Z-NO-SUCH-PIN": -25000,
		}}}
		err := data.applyPhaseAdjustments(profile, opts)
		if !assert.Error(t, err) {
			return
		}
		assert.Empty(t, writer.adjustments)
	})

	t.Run("writer error is returned", func(t *testing.T) {
		t.Parallel()
		writer := &fakeE825PhaseAdjustmentWriter{err: errors.New("netlink write failed")}
		data := E825PluginData{
			dpllPins:              []*dpll.PinInfo{testE825Pin(5, "OUT2P", "HPE-OUT2P", testE825ClockID)},
			phaseAdjustmentWriter: writer,
		}
		profile := &ptpv1.PtpProfile{PtpSettings: map[string]string{"clockId[eno5]": "4660"}}
		opts := E825Opts{PhaseAdjustments: map[string]map[string]int64{"eno5": {"HPE-OUT2P": 0}}}
		err := data.applyPhaseAdjustments(profile, opts)
		if !assert.Error(t, err) {
			return
		}
		assert.ErrorContains(t, err, "netlink write failed")
		assert.Len(t, writer.adjustments, 1)
	})
}

func TestOnPTPConfigChangeE825AppliesConfiguredPhaseAdjustments(t *testing.T) {
	mockPinConfig, restorePinConfig := setupMockPinConfig()
	defer restorePinConfig()

	profile, err := loadProfile("./testdata/e825-tgm.yaml")
	if !assert.NoError(t, err) {
		return
	}
	profile.Plugins[pluginNameE825].Raw = []byte(`{"devices":["eno5"],"gnss":{"disabled":true},"phaseAdjustments":{"eno5":{"REF0P":-8600}}}`)

	previousGetAllDpllDevices := getAllDpllDevices
	getAllDpllDevices = func() ([]*dpll.DoDeviceGetReply, error) {
		return []*dpll.DoDeviceGetReply{{ModuleName: "zl3073x", Type: 1, ClockID: testE825ClockID}}, nil
	}
	defer func() { getAllDpllDevices = previousGetAllDpllDevices }()

	plugin, dataRef := E825(pluginNameE825)
	data := (*dataRef).(*E825PluginData)
	batchPinSet, restoreBatchPinSet := setupGNSSMocks(data)
	defer restoreBatchPinSet()
	data.dpllPins = append(data.dpllPins, testE825Pin(3, "REF0P", "PACKAGE-REF0P", testE825ClockID))
	writer := &fakeE825PhaseAdjustmentWriter{}
	data.phaseAdjustmentWriter = writer

	err = plugin.OnPTPConfigChange(dataRef, profile)
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, 1, len(batchPinSet.commands))
	assert.Len(t, writer.adjustments, 1)
	assert.Equal(t, uint32(3), writer.adjustments[0].pinID)
	assert.Equal(t, int32(-8600), writer.adjustments[0].phaseAdjust)
	assert.Equal(t, 0, mockPinConfig.actualPinSetCount)
}
