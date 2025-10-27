# Holdover Parameters Integration

This document describes how to use holdover parameters from HardwareConfig in the DPLL subsystem.

## Overview

Holdover parameters define how the DPLL complex behaves when it loses its reference signal. Previously these were hardcoded or profile-specific. Now they can be configured per-subsystem via HardwareConfig.

## HardwareConfig YAML Example

```yaml
apiVersion: ptp.openshift.io/v1
kind: HardwareConfig
metadata:
  name: my-hardware-config
  namespace: openshift-ptp
spec:
  relatedPtpProfileName: my-ptp-profile
  profile:
    clockChain:
      structure:
        - name: "TBC WPC leader"
          dpll:
            clockId: "0x507c6fffff1fb1b8"
            holdoverParameters:
              maxInSpecOffset: 200           # ns - holdover specification threshold
              localMaxHoldoverOffset: 2000   # ns - maximum holdover offset  
              localHoldoverTimeout: 7200     # seconds - holdover timeout
```

## API Usage

### In Hardware Config Manager

The hardware config manager automatically extracts and stores holdover parameters:

```go
// When UpdateHardwareConfig is called, holdover parameters are extracted
hcm := hardwareconfig.NewHardwareConfigManager()
err := hcm.UpdateHardwareConfig(hwConfigs)
```

### Retrieving Holdover Parameters

To retrieve holdover parameters for a specific DPLL clock:

```go
// Get holdover parameters for a clock ID
profileName := "my-ptp-profile"
clockID := uint64(0x507c6fffff1fb1b8)

params := hcm.GetHoldoverParameters(profileName, clockID)
if params != nil {
    // Use the parameters
    maxInSpec := params.MaxInSpecOffset
    localMaxOffset := params.LocalMaxHoldoverOffset  
    timeout := params.LocalHoldoverTimeout
}
```

### Default Values

If holdover parameters are omitted or set to 0, defaults are applied:
- `MaxInSpecOffset`: 100 ns
- `LocalMaxHoldoverOffset`: 1500 ns  
- `LocalHoldoverTimeout`: 14400 seconds (4 hours)

## Integration with DPLL

To use these parameters in DPLL initialization (to be implemented in pkg/dpll):

```go
// In DPLL initialization code:
func NewDpllConfig(profileName string, clockID uint64, hcm *hardwareconfig.HardwareConfigManager, ...) (*DpllConfig, error) {
    d := &DpllConfig{
        // ... other fields ...
    }
    
    // Try to get holdover parameters from hardware config
    if hcm != nil {
        if params := hcm.GetHoldoverParameters(profileName, clockID); params != nil {
            d.MaxInSpecOffset = params.MaxInSpecOffset
            d.LocalHoldoverTimeout = params.LocalHoldoverTimeout
            // Note: LocalMaxHoldoverOffset is calculated from slope in current implementation
            glog.Infof("Using holdover params from HardwareConfig: MaxInSpec=%dns, Timeout=%ds",
                params.MaxInSpecOffset, params.LocalHoldoverTimeout)
        } else {
            // Fall back to defaults or profile-specific values
            d.MaxInSpecOffset = getDefaultMaxInSpecOffset()
            d.LocalHoldoverTimeout = getDefaultHoldoverTimeout()
        }
    }
    
    return d, nil
}
```

## Benefits

1. **Centralized Configuration**: Holdover parameters are now part of the HardwareConfig CRD
2. **Per-Subsystem Granularity**: Different DPLLs can have different holdover parameters
3. **Backward Compatible**: Falls back to defaults if not specified
4. **Declarative**: Hardware behavior is fully described in the config, not hardcoded

## Testing

See `TestHoldoverParametersExtraction` in `hardwareconfig_test.go` for usage examples.

