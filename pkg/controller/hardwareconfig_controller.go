package controller

import (
	"context"
	"time"

	"github.com/golang/glog"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/types"
)

// HardwareConfigUpdateHandler defines the interface for handling hardware configuration updates
type HardwareConfigUpdateHandler interface {
	UpdateHardwareConfig(hwConfigs []types.HardwareProfile) error
}

// HardwareConfigReconciler reconciles HardwareConfig objects and provides hardware configuration updates to the daemon
type HardwareConfigReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// NodeName is the name of the node this daemon is running on
	NodeName string

	// HardwareConfigHandler handles hardware configuration updates
	HardwareConfigHandler HardwareConfigUpdateHandler

	// ConfigUpdate is used to trigger PTP process restarts when hardware config changes
	// affect currently active PTP profiles
	ConfigUpdate HardwareConfigRestartTrigger
}

// HardwareConfigRestartTrigger interface for triggering PTP restarts
type HardwareConfigRestartTrigger interface {
	TriggerRestartForHardwareChange() error
	GetCurrentPTPProfiles() []string
}

// +kubebuilder:rbac:groups=ptp.openshift.io,resources=hardwareconfigs,verbs=get;list;watch
// +kubebuilder:rbac:groups=ptp.openshift.io,resources=hardwareconfigs/status,verbs=get;update;patch

// Reconcile handles HardwareConfig changes and updates the daemon hardware configuration
func (r *HardwareConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	glog.Infof("Reconciling HardwareConfig name=%s namespace=%s", req.Name, req.Namespace)

	// Get the HardwareConfig resource
	hwConfig := &types.HardwareConfig{}
	err := r.Get(ctx, req.NamespacedName, hwConfig)
	if err != nil {
		if errors.IsNotFound(err) {
			// HardwareConfig was deleted, trigger recalculation of hardware configurations
			glog.Infof("HardwareConfig deleted, recalculating hardware configurations name=%s", req.Name)
			return r.reconcileAllConfigs(ctx)
		}
		glog.Errorf("Failed to get HardwareConfig: %v", err)
		return ctrl.Result{}, err
	}

	// Recalculate and apply hardware configuration for this node
	return r.reconcileAllConfigs(ctx)
}

// reconcileAllConfigs calculates the effective hardware configuration for this node by examining all HardwareConfigs
func (r *HardwareConfigReconciler) reconcileAllConfigs(ctx context.Context) (ctrl.Result, error) {
	// List all HardwareConfigs in the cluster
	hwConfigList := &types.HardwareConfigList{}
	if err := r.List(ctx, hwConfigList); err != nil {
		glog.Errorf("Failed to list HardwareConfigs: %v", err)
		return ctrl.Result{}, err
	}

	// Check if any hardware configs are associated with currently active PTP profiles
	// If so, trigger a PTP restart to ensure hardware and PTP configurations are synchronized
	needsPTPRestart := r.checkIfActiveProfilesAffected(ctx, hwConfigList.Items)

	if needsPTPRestart {
		glog.Infof("HardwareConfig change affects active PTP profiles on node %s, will trigger PTP restart after reconciling all configs", r.NodeName)
		// Don't trigger restart immediately - wait for all configs to be reconciled first
		r.scheduleDeferredRestart(ctx)
	}

	// Calculate the applicable hardware configurations for this node
	applicableConfigs, err := r.calculateNodeHardwareConfigs(ctx, hwConfigList.Items)
	if err != nil {
		glog.Errorf("Failed to calculate node hardware configurations: %v", err)
		return ctrl.Result{}, err
	}

	// Apply hardware configurations via the handler
	if len(applicableConfigs) > 0 {
		glog.Infof("Updating daemon hardware configuration with %d device configs for node %s", len(applicableConfigs), r.NodeName)

		// Send hardware configuration update to daemon
		if r.HardwareConfigHandler != nil {
			err = r.HardwareConfigHandler.UpdateHardwareConfig(applicableConfigs)
			if err != nil {
				glog.Errorf("Failed to update daemon hardware configuration: %v", err)
				return ctrl.Result{}, err
			}
		}

		glog.Infof("Successfully updated daemon hardware configuration deviceConfigs=%d", len(applicableConfigs))
	} else {
		glog.Infof("No applicable hardware configurations found for node %s", r.NodeName)

		// Clear hardware configurations if needed
		if r.HardwareConfigHandler != nil {
			err = r.HardwareConfigHandler.UpdateHardwareConfig([]types.HardwareProfile{})
			if err != nil {
				glog.Errorf("Failed to clear daemon hardware configuration: %v", err)
				return ctrl.Result{}, err
			}
		}
	}

	return ctrl.Result{}, nil
}

// scheduleDeferredRestart schedules a restart to happen after a short delay
// This allows all HardwareConfig reconciliations to complete before triggering the restart
func (r *HardwareConfigReconciler) scheduleDeferredRestart(ctx context.Context) {
	// Use a goroutine with a short delay to allow all reconciliations to complete
	go func() {
		// Wait a short time for all reconciliations to complete
		time.Sleep(100 * time.Millisecond)

		if r.ConfigUpdate != nil {
			err := r.ConfigUpdate.TriggerRestartForHardwareChange()
			if err != nil {
				glog.Errorf("Failed to trigger deferred PTP restart for hardware configuration change: %v", err)
			} else {
				glog.Infof("Successfully triggered deferred PTP restart due to hardware configuration change")
			}
		}
	}()
}

// calculateNodeHardwareConfigs determines which hardware configurations should be applied to this node
func (r *HardwareConfigReconciler) calculateNodeHardwareConfigs(ctx context.Context, hwConfigs []types.HardwareConfig) ([]types.HardwareProfile, error) {
	var applicableProfiles []types.HardwareProfile

	// For now, we apply all hardware configurations to all nodes
	// This can be enhanced later with node matching logic similar to PtpConfig
	for _, hwConfig := range hwConfigs {
		glog.Infof("Processing HardwareConfig name=%s profile=%s", hwConfig.Name, getProfileName(hwConfig.Spec.Profile))

		// TODO: Add node-specific filtering logic here
		// For now, we include all hardware profiles
		applicableProfiles = append(applicableProfiles, hwConfig.Spec.Profile)
		glog.Infof("Added hardware profile profileName=%s relatedPtpProfile=%s", getProfileName(hwConfig.Spec.Profile), hwConfig.Spec.RelatedPtpProfileName)
	}

	glog.Infof("Calculated hardware configurations for node node=%s totalProfiles=%d", r.NodeName, len(applicableProfiles))
	return applicableProfiles, nil
}

// checkIfActiveProfilesAffected determines if hardware config changes should trigger PTP restart
// We restart whenever hardware configs change to ensure PTP and hardware configurations stay synchronized
func (r *HardwareConfigReconciler) checkIfActiveProfilesAffected(ctx context.Context, hwConfigs []types.HardwareConfig) bool {
	// Get currently active PTP profiles from the daemon
	if r.ConfigUpdate == nil {
		glog.Infof("No ConfigUpdate interface available, cannot check active PTP profiles")
		return false
	}

	activePTPProfiles := r.ConfigUpdate.GetCurrentPTPProfiles()
	glog.Infof("Hardware config change detected, will trigger PTP restart activeProfiles=%v hardwareConfigs=%d", activePTPProfiles, len(hwConfigs))

	// Always restart when hardware configs change, as long as there are active PTP profiles
	// This ensures PTP and hardware configurations remain synchronized
	if len(activePTPProfiles) > 0 {
		glog.Infof("Triggering PTP restart due to hardware configuration change")
		return true
	}

	glog.Infof("No active PTP profiles, skipping hardware config restart")
	return false
}

// getProfileName safely extracts the profile name from a HardwareProfile
func getProfileName(profile types.HardwareProfile) string {
	if profile.Name != nil {
		return *profile.Name
	}
	return "unnamed"
}

// SetupWithManager sets up the controller with the Manager
func (r *HardwareConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Watch HardwareConfig resources
	return ctrl.NewControllerManagedBy(mgr).
		For(&types.HardwareConfig{}).
		WithOptions(controller.Options{
			// Use a custom reconciler name for logging
			RecoverPanic: func() *bool { v := true; return &v }(),
		}).
		Complete(r)
}
