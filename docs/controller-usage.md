# LinuxPTP Daemon with Kubernetes Controller

This document describes how to use the LinuxPTP daemon with Kubernetes controller support for watching `PtpConfig` custom resources.

## Overview

The LinuxPTP daemon now supports two modes of operation (controller mode is disabled by default; enable with `--use-controller=true`):

1. **Controller Mode**: Watches `PtpConfig` and `HardwareConfig` custom resources and automatically applies matching configurations
2. **Legacy File Mode**: Reads configuration from mounted ConfigMaps (backward compatibility)

## Controller Mode

### Features

- **Automatic Configuration**: Watches `PtpConfig` and `HardwareConfig` CRDs across the cluster
- **Node Matching**: Applies configurations based on node name and label selectors  
- **Priority-based Selection**: When multiple recommendations match, highest priority wins
- **Hardware Configuration**: Applies hardware-specific settings for PTP devices
- **Real-time Updates**: Configuration changes are applied automatically without restarts

### How It Works

1. The daemon starts with a Kubernetes controller manager
2. Controllers watch all `PtpConfig` and `HardwareConfig` resources in the cluster
3. For each config change, controllers evaluate configurations against current node
4. Matching profiles are converted to JSON and sent to the daemon's configuration system
5. Hardware configurations are applied to PTP-capable hardware devices  
6. Daemon applies the new configuration and restarts PTP processes as needed

### Configuration Flow

```
PtpConfig CRD → Controller → Node Matching → Profile Selection → Daemon Config Update → PTP Process Restart
HardwareConfig CRD → Controller → Check Active Profile Association → Unified Restart Trigger → PTP Process Restart
```

### Unified Restart Mechanism

Both PtpConfig and HardwareConfig controllers use the same unified restart mechanism:

1. **PtpConfig Changes**: Always trigger a complete PTP process restart immediately
2. **HardwareConfig Changes**: Check if the hardware config is associated with a currently active PTP profile via the `RelatedPtpProfileName` field
   - If associated: Schedule a **deferred restart** after all configurations are reconciled
   - If not associated: Only update hardware configuration without restart
3. **Unified Signal**: Both controllers use the same `UpdateCh` channel to signal the daemon
4. **Deferred Execution**: HardwareConfig changes use a 100ms delay to ensure all reconciliations complete before triggering restart
5. **Complete Restart**: The daemon performs a complete stop/restart cycle, ensuring both PTP and hardware configurations are applied consistently

### Node Matching Logic

The controller evaluates `PtpConfig.spec.recommend` rules to determine which profile to apply:

1. **No Match Rules**: If `match` is empty, the recommendation applies to all nodes
2. **Node Name**: Direct node name matching (`nodeName: "worker-1"`)
3. **Node Labels**: Label key matching (`nodeLabel: "node-role.kubernetes.io/worker"`)
4. **OR Logic**: Any matching rule in the `match` array will select the recommendation
5. **Priority**: Highest priority recommendation wins when multiple match

### Example PtpConfig

```yaml
apiVersion: ptp.openshift.io/v1
kind: PtpConfig
metadata:
  name: worker-ptp-config
  namespace: openshift-ptp
spec:
  profile:
  - name: "ordinary-clock"
    interface: "ens1f0"
    ptp4lOpts: "-s -2"
    phc2sysOpts: "-a -r"
    ptp4lConf: |
      [global]
      slaveOnly 1
      # ... more ptp4l configuration
      
  recommend:
  - profile: "ordinary-clock"
    priority: 10
    match:
    - nodeLabel: "node-role.kubernetes.io/worker"
```

### Example HardwareConfig

```yaml
apiVersion: ptp.openshift.io/v2alpha1
kind: HardwareConfig
metadata:
  name: test
  namespace: openshift-ptp
spec:
  relatedPtpProfileName: 01-tbc-tr
  profile:
    name: "tbc"
    clockChain:
      structure:
      - name: leader-ens4f1
        ethernet:
          - ports: ["ens4f0","ens4f1","ens4f2","ens4f3"]
        dpll:
          phaseInputs:
            CVL_SDP22:
              frequency: 1
              description: PTP time receiver input
          phaseOutputs:
            REF-SMA1:
              connector: SMA1 
              frequency: 1 

```

### Deployment

The daemon deployment includes:

```yaml
containers:
- name: linuxptp-daemon-container
  args: ["/usr/local/bin/ptp --alsologtostderr --use-controller=true"]
  ports:
  - name: metrics
    containerPort: 9091
  - name: health  
    containerPort: 8081
  - name: controller-health
    containerPort: 8082
```

### RBAC Requirements

Controller mode requires additional cluster-level permissions:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: linuxptp-daemon-cluster-role
rules:
- apiGroups: [""]
  resources: ["nodes"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["ptp.openshift.io"]
  resources: ["ptpconfigs"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["ptp.openshift.io"]
  resources: ["ptpconfigs/status"]
  verbs: ["get", "update", "patch"]
- apiGroups: ["ptp.openshift.io"]
  resources: ["hardwareconfigs"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["ptp.openshift.io"]
  resources: ["hardwareconfigs/status"]
  verbs: ["get", "update", "patch"]
```

## Command Line Options

- `--use-controller=true/false`: Enable/disable controller mode (default: false)
- `--update-interval=30`: Status update interval in seconds
- `--pmc-poll-interval=2`: PMC polling interval in seconds

## Health Checks

The controller exposes health endpoints:

- `:8081/healthz` - Daemon health
- `:8082/healthz` - Controller health  
- `:8082/readyz` - Controller readiness

## Monitoring

Metrics are available on `:9091/metrics` (when not using socket mode).

## Troubleshooting

### Check Controller Status

```bash
# Check if controller is running
curl http://localhost:8082/healthz

# Check daemon logs
kubectl logs -n openshift-ptp linuxptp-daemon-<pod> -c linuxptp-daemon-container
```

### Debug Configuration Matching

Look for these log messages:

```
Processing PtpConfig name=example-ptp-config profiles=2 recommendations=1
Found matching recommendation profile=ordinary-clock priority=10
Added profile to node configuration profile=ordinary-clock
Updating daemon configuration with 1 profiles for node worker-1
```

### Common Issues

1. **No matching profiles**: Check node labels and recommendation match rules
2. **Controller not starting**: Verify RBAC permissions and cluster connectivity
3. **Config not applying**: Check controller logs for reconciliation errors

## Migration from File Mode

To migrate from file-based configuration:

1. Deploy new RBAC permissions
2. Create equivalent `PtpConfig` resources
3. Update daemon deployment to remove ConfigMap volumes  
4. Set `--use-controller=true`
5. Remove old ConfigMaps after verification

## Legacy File Mode

For backward compatibility, file mode can still be used:

```bash
/usr/local/bin/ptp --use-controller=false --linuxptp-profile-path=/etc/linuxptp
```

This mode reads configuration from mounted ConfigMap files as before.