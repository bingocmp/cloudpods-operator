// Copyright 2019 Yunion
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package component

import (
	apps "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"

	"yunion.io/x/onecloud-operator/pkg/apis/constants"
	"yunion.io/x/onecloud-operator/pkg/apis/onecloud/v1alpha1"
	"yunion.io/x/onecloud-operator/pkg/controller"
	"yunion.io/x/onecloud-operator/pkg/manager"
	"yunion.io/x/onecloud-operator/pkg/service-init/component"
)

type generalServiceManager struct {
	*ComponentManager
}

func newGeneralServiceManager(man *ComponentManager) manager.Manager {
	return &generalServiceManager{man}
}

func (m *generalServiceManager) getProductVersions() []v1alpha1.ProductVersion {
	return []v1alpha1.ProductVersion{
		v1alpha1.ProductVersionFullStack,
		v1alpha1.ProductVersionCMP,
		v1alpha1.ProductVersionEdge,
	}
}

func (m *generalServiceManager) getComponentType() v1alpha1.ComponentType {
	return v1alpha1.GeneralServiceComponentType
}

func (m *generalServiceManager) Sync(oc *v1alpha1.OnecloudCluster) error {
	return syncComponent(m, oc, oc.Spec.GeneralService.Disable, "")
}

func (m *generalServiceManager) getDBConfig(cfg *v1alpha1.OnecloudClusterConfig) *v1alpha1.DBConfig {
	return &cfg.GeneralService.DB
}

func (m *generalServiceManager) getClickhouseConfig(cfg *v1alpha1.OnecloudClusterConfig) *v1alpha1.DBConfig {
	return &cfg.GeneralService.ClickhouseConf
}

func (m *generalServiceManager) getCloudUser(cfg *v1alpha1.OnecloudClusterConfig) *v1alpha1.CloudUser {
	return &cfg.GeneralService.CloudUser
}

func (m *generalServiceManager) getPhaseControl(man controller.ComponentManager, zone string) controller.PhaseControl {
	return component.NewGeneralService().GetPhaseControl(man)
}

func (m *generalServiceManager) getConfigMap(oc *v1alpha1.OnecloudCluster, cfg *v1alpha1.OnecloudClusterConfig, zone string) (*corev1.ConfigMap, bool, error) {
	opt, err := component.NewGeneralService().GetConfig(oc, cfg)
	if err != nil {
		return nil, false, err
	}

	return m.newServiceConfigMap(v1alpha1.GeneralServiceComponentType, zone, oc, opt), false, nil
}

func (m *generalServiceManager) getService(oc *v1alpha1.OnecloudCluster, cfg *v1alpha1.OnecloudClusterConfig, zone string) []*corev1.Service {
	return []*corev1.Service{m.newSingleNodePortService(v1alpha1.GeneralServiceComponentType, oc, int32(oc.Spec.GeneralService.Service.NodePort), int32(cfg.GeneralService.Port))}
}

func (m *generalServiceManager) getDeployment(oc *v1alpha1.OnecloudCluster, cfg *v1alpha1.OnecloudClusterConfig, zone string) (*apps.Deployment, error) {
	return m.newCloudServiceSinglePortDeployment(v1alpha1.GeneralServiceComponentType, "", oc, &oc.Spec.GeneralService.DeploymentSpec, constants.GeneralServicePort, true, false)
}

func (m *generalServiceManager) getDeploymentStatus(oc *v1alpha1.OnecloudCluster, zone string) *v1alpha1.DeploymentStatus {
	return &oc.Status.GeneralService
}
