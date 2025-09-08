package controller

import (
	"context"

	"github.com/golang/glog"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/log"

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
	log := log.FromContext(ctx)
	log.Info("Reconciling HardwareConfig", "name", req.Name, "namespace", req.Namespace)

	// Get the HardwareConfig resource
	hwConfig := &types.HardwareConfig{}
	err := r.Get(ctx, req.NamespacedName, hwConfig)
	if err != nil {
		if errors.IsNotFound(err) {
			// HardwareConfig was deleted, trigger recalculation of hardware configurations
			log.Info("HardwareConfig deleted, recalculating hardware configurations", "name", req.Name)
			return r.reconcileAllConfigs(ctx)
		}
		log.Error(err, "Failed to get HardwareConfig")
		return ctrl.Result{}, err
	}

	// Recalculate and apply hardware configuration for this node
	return r.reconcileAllConfigs(ctx)
}

// reconcileAllConfigs calculates the effective hardware configuration for this node by examining all HardwareConfigs
func (r *HardwareConfigReconciler) reconcileAllConfigs(ctx context.Context) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// List all HardwareConfigs in the cluster
	hwConfigList := &types.HardwareConfigList{}
	if err := r.List(ctx, hwConfigList); err != nil {
		log.Error(err, "Failed to list HardwareConfigs")
		return ctrl.Result{}, err
	}

	// Check if any hardware configs are associated with currently active PTP profiles
	// If so, trigger a PTP restart to ensure hardware and PTP configurations are synchronized
	needsPTPRestart := r.checkIfActiveProfilesAffected(ctx, hwConfigList.Items)

	if needsPTPRestart {
		glog.Infof("HardwareConfig change affects active PTP profiles on node %s, triggering PTP restart", r.NodeName)
		if r.ConfigUpdate != nil {
			err := r.ConfigUpdate.TriggerRestartForHardwareChange()
			if err != nil {
				log.Error(err, "Failed to trigger PTP restart for hardware configuration change")
				return ctrl.Result{}, err
			}
			log.Info("Successfully triggered PTP restart due to hardware configuration change")
			// When PTP restarts, it will pick up the new hardware configurations automatically
			return ctrl.Result{}, nil
		}
	}

	// Calculate the applicable hardware configurations for this node
	applicableConfigs, err := r.calculateNodeHardwareConfigs(ctx, hwConfigList.Items)
	if err != nil {
		log.Error(err, "Failed to calculate node hardware configurations")
		return ctrl.Result{}, err
	}

	// Apply hardware configurations via the handler
	if len(applicableConfigs) > 0 {
		glog.Infof("Updating daemon hardware configuration with %d device configs for node %s", len(applicableConfigs), r.NodeName)

		// Send hardware configuration update to daemon
		if r.HardwareConfigHandler != nil {
			err = r.HardwareConfigHandler.UpdateHardwareConfig(applicableConfigs)
			if err != nil {
				log.Error(err, "Failed to update daemon hardware configuration")
				return ctrl.Result{}, err
			}
		}

		log.Info("Successfully updated daemon hardware configuration", "deviceConfigs", len(applicableConfigs))
	} else {
		glog.Infof("No applicable hardware configurations found for node %s", r.NodeName)

		// Clear hardware configurations if needed
		if r.HardwareConfigHandler != nil {
			err = r.HardwareConfigHandler.UpdateHardwareConfig([]types.HardwareProfile{})
			if err != nil {
				log.Error(err, "Failed to clear daemon hardware configuration")
				return ctrl.Result{}, err
			}
		}
	}

	return ctrl.Result{}, nil
}

// calculateNodeHardwareConfigs determines which hardware configurations should be applied to this node
func (r *HardwareConfigReconciler) calculateNodeHardwareConfigs(ctx context.Context, hwConfigs []types.HardwareConfig) ([]types.HardwareProfile, error) {
	log := log.FromContext(ctx)

	var applicableProfiles []types.HardwareProfile

	// For now, we apply all hardware configurations to all nodes
	// This can be enhanced later with node matching logic similar to PtpConfig
	for _, hwConfig := range hwConfigs {
		log.Info("Processing HardwareConfig", "name", hwConfig.Name, "profile", getProfileName(hwConfig.Spec.Profile))

		// TODO: Add node-specific filtering logic here
		// For now, we include all hardware profiles
		applicableProfiles = append(applicableProfiles, hwConfig.Spec.Profile)
		log.Info("Added hardware profile", "profileName", getProfileName(hwConfig.Spec.Profile), "relatedPtpProfile", hwConfig.Spec.RelatedPtpProfileName)
	}

	log.Info("Calculated hardware configurations for node", "node", r.NodeName, "totalProfiles", len(applicableProfiles))
	return applicableProfiles, nil
}

// checkIfActiveProfilesAffected determines if any hardware configs are associated with currently active PTP profiles
func (r *HardwareConfigReconciler) checkIfActiveProfilesAffected(ctx context.Context, hwConfigs []types.HardwareConfig) bool {
	log := log.FromContext(ctx)

	// Get currently active PTP profiles from the daemon
	if r.ConfigUpdate == nil {
		log.Info("No ConfigUpdate interface available, cannot check active PTP profiles")
		return false
	}

	activePTPProfiles := r.ConfigUpdate.GetCurrentPTPProfiles()
	if len(activePTPProfiles) == 0 {
		log.Info("No active PTP profiles found")
		return false
	}

	log.Info("Checking hardware config associations", "activeProfiles", activePTPProfiles, "hardwareConfigs", len(hwConfigs))

	// Check if any hardware config is associated with an active PTP profile
	for _, hwConfig := range hwConfigs {
		if hwConfig.Spec.RelatedPtpProfileName != "" {
			for _, activeProfile := range activePTPProfiles {
				if hwConfig.Spec.RelatedPtpProfileName == activeProfile {
					log.Info("Found hardware config associated with active PTP profile",
						"hardwareConfig", hwConfig.Name,
						"relatedProfile", hwConfig.Spec.RelatedPtpProfileName,
						"activeProfile", activeProfile)
					return true
				}
			}
		}
	}

	log.Info("No hardware configs are associated with currently active PTP profiles")
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
