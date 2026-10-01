package daemon

import (
	"slices"

	"github.com/golang/glog"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/addons"
	"github.com/k8snetworkplumbingwg/linuxptp-daemon/pkg/plugin"
)

func registerPlugins(plugins []string) (plugin.PluginManager, []string) {
	glog.Infof("Begin plugin registration...")
	allowed := make([]string, 0, len(mapping.PluginMapping))
	for name := range mapping.PluginMapping {
		allowed = append(allowed, name)
	}
	slices.Sort(allowed)
	glog.Infof("Allowed hardware plugins: %v; requested at startup: %v", allowed, plugins)
	manager := plugin.PluginManager{Plugins: make(map[string]*plugin.Plugin),
		Data: make(map[string]*interface{}),
	}
	var unknownPlugins []string
	for _, name := range plugins {
		currentPlugin, currentData := registerPlugin(name)
		if currentPlugin != nil {
			manager.Plugins[name] = currentPlugin
			manager.Data[name] = currentData
		} else {
			unknownPlugins = append(unknownPlugins, name)
		}
	}
	registered := make([]string, 0, len(manager.Plugins))
	for name := range manager.Plugins {
		registered = append(registered, name)
	}
	slices.Sort(registered)
	glog.Infof("Registered hardware plugins: %v; unknown startup plugins: %v", registered, unknownPlugins)
	return manager, unknownPlugins
}

func registerPlugin(name string) (*plugin.Plugin, *interface{}) {
	glog.Infof("Trying to register plugin: " + name)
	for mName, mConstructor := range mapping.PluginMapping {
		if mName == name {
			return mConstructor(name)
		}
	}
	glog.Errorf("Plugin not found: " + name)
	return nil, nil
}
