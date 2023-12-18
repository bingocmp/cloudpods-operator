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

package models

import (
	"context"

	"yunion.io/x/jsonutils"
	"yunion.io/x/pkg/util/rbacscope"
	"yunion.io/x/sqlchemy"

	api "yunion.io/x/onecloud/pkg/apis/compute"
	"yunion.io/x/onecloud/pkg/cloudcommon/db"
	"yunion.io/x/onecloud/pkg/mcclient"
	"yunion.io/x/onecloud/pkg/util/stringutils2"
)

type SExternalMachineManager struct {
	db.SEnabledStatusStandaloneResourceBaseManager
	db.SProjectizedResourceBaseManager
}

var ExternalMachineManager *SExternalMachineManager

func init() {
	ExternalMachineManager = &SExternalMachineManager{
		SEnabledStatusStandaloneResourceBaseManager: db.NewEnabledStatusStandaloneResourceBaseManager(
			SExternalMachine{},
			"externalmachines_tbl",
			"externalmachine",
			"externalmachines",
		),
	}
	ExternalMachineManager.SetVirtualObject(ExternalMachineManager)
}

type SExternalMachine struct {
	db.SMultiArchResourceBase
	db.SEnabledStatusStandaloneResourceBase
	db.SProjectizedResourceBase

	// CPU大小
	CpuCount int `nullable:"false" default:"2" list:"user" update:"user" create:"optional"`

	// 内存大小, 单位Mb
	MemSize int `nullable:"false" default:"2048" list:"user" update:"user" create:"required"`

	// 操作系统类型
	OsType string `width:"36" nullable:"true" list:"user" update:"user" create:"optional"`

	Project string `width:"100" nullable:"true" list:"user" update:"user"`

	Domain string `width:"100" nullable:"true" list:"user" update:"user"`

	IpAddr string `width:"36" nullable:"true" list:"user" update:"user" create:"optional"`

	Port int `nullable:"false" default:"22" list:"user" update:"user" create:"required"`

	MachineConfig *jsonutils.JSONDict `get:"user" nullable:"true" list:"user" update:"user" create:"optional"`

	UserName string `width:"36" nullable:"false" list:"user" update:"user" create:"required"`

	Password string `width:"36" nullable:"false" list:"user" update:"user" create:"required"`
}

func (manager *SExternalMachineManager) FetchCustomizeColumns(ctx context.Context, userCred mcclient.TokenCredential, query jsonutils.JSONObject, objs []interface{}, fields stringutils2.SSortedStrings, isList bool) []api.ExternalMachineDetails {
	rows := make([]api.ExternalMachineDetails, len(objs))
	return rows
}

func (manager *SExternalMachineManager) ResourceScope() rbacscope.TRbacScope {
	return rbacscope.ScopeProject
}

func (em *SExternalMachine) CustomizeCreate(ctx context.Context, userCred mcclient.TokenCredential, ownerId mcclient.IIdentityProvider, query jsonutils.JSONObject, data jsonutils.JSONObject) error {
	em.SetEnabled(true)
	em.ProjectId = ownerId.GetProjectId()
	em.Project = ownerId.GetProjectName()
	em.DomainId = ownerId.GetDomainId()
	em.Domain = ownerId.GetDomainName()
	return nil
}

func (manager *SExternalMachineManager) ListItemFilter(ctx context.Context, q *sqlchemy.SQuery, userCred mcclient.TokenCredential, input api.ExternalMachineListInput) (*sqlchemy.SQuery, error) {
	q, err := manager.SStatusStandaloneResourceBaseManager.ListItemFilter(ctx, q, userCred, input.StatusStandaloneResourceListInput)
	if err != nil {
		return q, err
	}
	if len(input.OsArch) > 0 {
		q = q.Equals("os_arch", input.OsArch)
	}
	if len(input.OsType) > 0 {
		q = q.Equals("os_type", input.OsType)
	}
	return q, nil
}

func (manager *SExternalMachineManager) OrderByExtraFields(ctx context.Context, q *sqlchemy.SQuery, userCred mcclient.TokenCredential, query api.ExternalMachineListInput) (*sqlchemy.SQuery, error) {
	return q, nil
}

func (manager *SExternalMachineManager) QueryDistinctExtraField(q *sqlchemy.SQuery, field string) (*sqlchemy.SQuery, error) {
	return q, nil
}

func (manager *SExternalMachineManager) ListItemExportKeys(ctx context.Context, q *sqlchemy.SQuery, userCred mcclient.TokenCredential, keys stringutils2.SSortedStrings) (*sqlchemy.SQuery, error) {
	return q, nil
}

func (manager *SExternalMachineManager) AllowDuplicateName() bool {
	return true
}
