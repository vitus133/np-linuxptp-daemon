package clock

import (
	"sync/atomic"

	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/utils"
)

var sourceGeneration atomic.Uint64

// PTPPortSource identifies a physical upstream PTP port. Other input kinds can
// implement utils.QualificationSource without depending on PTP port names.
type PTPPortSource struct {
	Port string
}

// Equal reports whether other identifies the same PTP port.
func (s PTPPortSource) Equal(other utils.QualificationSource) bool {
	port, ok := other.(PTPPortSource)
	return ok && s.Port == port.Port
}

// String returns the PTP port's interface name.
func (s PTPPortSource) String() string { return s.Port }

// PTPInstanceSource identifies the ptp4l clock servo as the qualification source.
// Unlike PTPPortSource it is stable across a BMCA port switchover: the servo (and
// its offset) is what is being qualified, not the physical ingress port, so
// selecting a new active TR port must not reset source readiness.
type PTPInstanceSource struct{}

// Equal reports whether other identifies the same ptp4l instance source.
func (PTPInstanceSource) Equal(other utils.QualificationSource) bool {
	_, ok := other.(PTPInstanceSource)
	return ok
}

// String returns the ptp4l instance source label.
func (PTPInstanceSource) String() string { return "ptp4l" }

type ptpSourceQualification struct {
	state                   *utils.QualificationState
	configuredUpstreamPorts []string
	lastSelectedPort        string
	available               bool
	generation              uint64
}

func (q *ptpSourceQualification) source() utils.QualificationSource {
	if q.lastSelectedPort == "" {
		return nil
	}
	return PTPInstanceSource{}
}
