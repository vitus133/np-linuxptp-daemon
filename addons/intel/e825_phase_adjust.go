package intel

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/golang/glog"
	dpllcore "github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/dpll"
	dpll "github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/dpll-netlink"
	ptpv1 "github.com/k8snetworkplumbingwg/ptp-operator/api/v1"
)

type e825PhaseAdjustment struct {
	device      string
	requested   string
	clockID     uint64
	pinID       uint32
	boardLabel  string
	phaseAdjust int32
}

type e825PhaseAdjustmentWriter interface {
	Apply([]e825PhaseAdjustment) error
}

type netlinkE825PhaseAdjustmentWriter struct{}

func (netlinkE825PhaseAdjustmentWriter) Apply(adjustments []e825PhaseAdjustment) error {
	conn, err := dpll.Dial(nil)
	if err != nil {
		return fmt.Errorf("failed to connect to DPLL netlink: %w", err)
	}
	//nolint:errcheck
	defer conn.Close()

	for _, adjustment := range adjustments {
		err = conn.PinPhaseAdjust(dpll.PinPhaseAdjustRequest{
			ID:          adjustment.pinID,
			PhaseAdjust: adjustment.phaseAdjust,
		})
		if err != nil {
			return fmt.Errorf("failed to adjust device %q pin %q (board label %q, clock ID %#x) to %d ps: %w",
				adjustment.device, adjustment.requested, adjustment.boardLabel, adjustment.clockID, adjustment.phaseAdjust, err)
		}
		glog.Infof("set e825 phase adjustment device=%q pin=%q boardLabel=%q clockID=%#x value=%d ps",
			adjustment.device, adjustment.requested, adjustment.boardLabel, adjustment.clockID, adjustment.phaseAdjust)
	}
	return nil
}

// allDevices includes interfaces named by phase-adjustment entries so their DPLL clock IDs are populated.
func (opts E825Opts) allDevices() []string {
	devices := opts.PluginOpts.allDevices()
	for device, adjustments := range opts.PhaseAdjustments {
		if len(adjustments) > 0 && strings.TrimSpace(device) != "" && !slices.Contains(devices, device) {
			devices = append(devices, device)
		}
	}
	return devices
}

func resolveE825PhaseAdjustments(profile *ptpv1.PtpProfile, opts E825Opts, pins []*dpll.PinInfo) ([]e825PhaseAdjustment, error) {
	devices := make([]string, 0, len(opts.PhaseAdjustments))
	for device, adjustments := range opts.PhaseAdjustments {
		if len(adjustments) > 0 {
			devices = append(devices, device)
		}
	}
	slices.Sort(devices)

	adjustments := make([]e825PhaseAdjustment, 0)
	type pinKey struct {
		clockID uint64
		pinID   uint32
	}
	seenPins := make(map[pinKey]string)
	for _, device := range devices {
		if strings.TrimSpace(device) == "" {
			return nil, fmt.Errorf("e825 phase adjustment device must not be empty")
		}
		clockIDKey := fmt.Sprintf("%s[%s]", dpllcore.ClockIdStr, device)
		clockIDStr, found := profile.PtpSettings[clockIDKey]
		if !found {
			return nil, fmt.Errorf("e825 phase adjustment device %q has no DPLL clock ID", device)
		}
		clockID, err := strconv.ParseUint(clockIDStr, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("e825 phase adjustment device %q has invalid DPLL clock ID %q: %w", device, clockIDStr, err)
		}
		if clockID == 0 {
			return nil, fmt.Errorf("e825 phase adjustment device %q has unresolved DPLL clock ID", device)
		}

		labels := make([]string, 0, len(opts.PhaseAdjustments[device]))
		for label := range opts.PhaseAdjustments[device] {
			labels = append(labels, label)
		}
		slices.Sort(labels)
		for _, label := range labels {
			if strings.TrimSpace(label) == "" {
				return nil, fmt.Errorf("e825 phase adjustment device %q has an empty pin label", device)
			}
			pin, err := resolveE825Pin(pins, label, clockID)
			if err != nil {
				return nil, fmt.Errorf("e825 phase adjustment device %q pin %q: %w", device, label, err)
			}
			key := pinKey{clockID: clockID, pinID: pin.ID}
			if previous, exists := seenPins[key]; exists {
				return nil, fmt.Errorf("e825 phase adjustments %q and %q resolve to the same DPLL pin ID %d", previous, device+":"+label, pin.ID)
			}
			seenPins[key] = device + ":" + label

			value, err := validateE825PhaseAdjustment(pin, opts.PhaseAdjustments[device][label])
			if err != nil {
				return nil, fmt.Errorf("e825 phase adjustment device %q pin %q: %w", device, label, err)
			}
			adjustments = append(adjustments, e825PhaseAdjustment{
				device:      device,
				requested:   label,
				clockID:     clockID,
				pinID:       pin.ID,
				boardLabel:  pin.BoardLabel,
				phaseAdjust: value,
			})
		}
	}
	return adjustments, nil
}

func resolveE825Pin(pins []*dpll.PinInfo, label string, clockID uint64) (*dpll.PinInfo, error) {
	boardMatches := make([]*dpll.PinInfo, 0, 1)
	packageMatches := make([]*dpll.PinInfo, 0, 1)
	for _, pin := range pins {
		if pin == nil || pin.ClockID != clockID {
			continue
		}
		if pin.BoardLabel == label {
			boardMatches = append(boardMatches, pin)
		}
		if pin.PackageLabel == label {
			packageMatches = append(packageMatches, pin)
		}
	}

	matches := boardMatches
	labelType := "board"
	if len(matches) == 0 {
		matches = packageMatches
		labelType = "package"
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("no DPLL pin has board or package label %q for clock ID %#x", label, clockID)
	}
	if len(matches) != 1 {
		return nil, fmt.Errorf("%d DPLL pins have %s label %q for clock ID %#x", len(matches), labelType, label, clockID)
	}
	return matches[0], nil
}

func validateE825PhaseAdjustment(pin *dpll.PinInfo, value int64) (int32, error) {
	const (
		minInt32 = -1 << 31
		maxInt32 = 1<<31 - 1
	)
	if value < minInt32 || value > maxInt32 {
		return 0, fmt.Errorf("value %d ps exceeds the DPLL phase-adjustment range", value)
	}
	if pin.PhaseAdjustMin != 0 && value < int64(pin.PhaseAdjustMin) {
		return 0, fmt.Errorf("value %d ps is below pin minimum %d ps", value, pin.PhaseAdjustMin)
	}
	if pin.PhaseAdjustMax != 0 && value > int64(pin.PhaseAdjustMax) {
		return 0, fmt.Errorf("value %d ps is above pin maximum %d ps", value, pin.PhaseAdjustMax)
	}
	if pin.PhaseAdjustGran > 1 && value%int64(pin.PhaseAdjustGran) != 0 {
		return 0, fmt.Errorf("value %d ps is not aligned to pin granularity %d ps", value, pin.PhaseAdjustGran)
	}
	return int32(value), nil
}

func (data *E825PluginData) applyPhaseAdjustments(profile *ptpv1.PtpProfile, opts E825Opts) error {
	if len(configuredE825AdjustmentDevices(opts.PhaseAdjustments)) == 0 {
		return nil
	}
	if len(data.dpllPins) == 0 {
		if err := data.populateDpllPins(); err != nil {
			return fmt.Errorf("failed to populate DPLL pins for e825 phase adjustment: %w", err)
		}
	}

	adjustments, err := resolveE825PhaseAdjustments(profile, opts, data.dpllPins)
	if err != nil {
		return err
	}
	if len(adjustments) == 0 {
		return nil
	}
	writer := data.phaseAdjustmentWriter
	if writer == nil {
		writer = netlinkE825PhaseAdjustmentWriter{}
	}
	if err = writer.Apply(adjustments); err != nil {
		return fmt.Errorf("failed to apply e825 phase adjustments: %w", err)
	}
	return nil
}

func configuredE825AdjustmentDevices(adjustments map[string]map[string]int64) []string {
	devices := make([]string, 0, len(adjustments))
	for device, pins := range adjustments {
		if len(pins) > 0 {
			devices = append(devices, device)
		}
	}
	return devices
}
