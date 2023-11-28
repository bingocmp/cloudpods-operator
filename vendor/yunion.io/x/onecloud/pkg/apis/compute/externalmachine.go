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

package compute

import (
	"yunion.io/x/cloudmux/pkg/apis/compute"

	"yunion.io/x/onecloud/pkg/apis"
)

const (
	EXTERNAL_MACHINE_STATUS_AVAILABLE   = compute.EXTERNAL_PROJECT_STATUS_AVAILABLE   // 可用
	EXTERNAL_MACHINE_STATUS_UNAVAILABLE = compute.EXTERNAL_PROJECT_STATUS_UNAVAILABLE // 不可用
	EXTERNAL_MACHINE_STATUS_CREATING    = compute.EXTERNAL_PROJECT_STATUS_CREATING    // 创建中
	EXTERNAL_MACHINE_STATUS_DELETING    = compute.EXTERNAL_PROJECT_STATUS_DELETING    // 删除中
	EXTERNAL_MACHINE_STATUS_UNKNOWN     = compute.EXTERNAL_PROJECT_STATUS_UNKNOWN     // 未知
)

var (
	MANGER_EXTERNAL_MACHINE_PROVIDERS = []string{
		CLOUD_PROVIDER_BINGO_CLOUD,
	}
)

type ExternalMachineDetails struct {
	apis.VirtualResourceDetails
}

type ExternalMachineCreateInput struct {
	apis.VirtualResourceCreateInput

	CloudaccountId string `json:"cloudaccount_id"`

	ManagerId string `json:"manager_id"`

	CpuCount int `json:"cpu_count"`

	MemSize int `json:"mem_size"`

	OsType string `json:"os_type"`
}

type ExternalMachineSshableMethodData struct {
	Method string
	Host   string
	Port   int

	Sshable bool
	Reason  string

	ForwardDetails ForwardDetails
}

type ExternalMachineMakeSshableInput struct {
	DryRun     bool
	User       string
	PrivateKey string
	Password   string
	IpAddr     string
	Port       int
}

type ExternalMachineMakeSshableOutput struct {
	AnsiblePlaybookId string
}

type ExternalMachineMakeSshableCmdOutput struct {
	ShellCmd string
}

type ExternalMachineSetSshportInput struct {
	Port int
}

type ExternalMachineSshportOutput struct {
	Port int
}

type ExternalMachineSshableOutput struct {
	User      string
	PublicKey string

	MethodTried []ExternalMachineSshableMethodData
}

type ExternalMachineHaveORFSInput struct {
}

type ExternalMachineHaveORBDInput struct {
}

type ExternalMachineHaveORFSOutput struct {
	Have bool
}

type ExternalMachineHaveORBDOutput struct {
	Have bool
}
