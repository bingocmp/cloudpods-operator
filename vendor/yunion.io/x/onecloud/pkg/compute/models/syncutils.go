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

	"yunion.io/x/cloudmux/pkg/cloudprovider"
	"yunion.io/x/log"
	"yunion.io/x/onecloud/pkg/apis"
	"yunion.io/x/onecloud/pkg/cloudcommon/db"
	"yunion.io/x/onecloud/pkg/mcclient"
	"yunion.io/x/pkg/util/timeutils"
	"yunion.io/x/pkg/utils"
)

type IMetadataSetter interface {
	SetCloudMetadataAll(ctx context.Context, meta map[string]string, userCred mcclient.TokenCredential) error
	SetSysCloudMetadataAll(ctx context.Context, meta map[string]string, userCred mcclient.TokenCredential) error
	Keyword() string
	GetName() string
	GetCloudproviderId() string
}

type IVirtualResourceMetadataSetter interface {
	IMetadataSetter
	SetSystemInfo(isSystem bool) error
}

func syncMetadata(ctx context.Context, userCred mcclient.TokenCredential, model IMetadataSetter, remote cloudprovider.ICloudResource) error {
	sysTags := remote.GetSysTags()
	sysStore := make(map[string]string, 0)
	for key, value := range sysTags {
		sysStore[db.SYS_CLOUD_TAG_PREFIX+key] = value
	}
	model.SetSysCloudMetadataAll(ctx, sysStore, userCred)

	tags, err := remote.GetTags()
	if err == nil {
		store := make(map[string]string, 0)
		for key, value := range tags {
			store[db.CLOUD_TAG_PREFIX+key] = value
		}
		model.SetCloudMetadataAll(ctx, store, userCred)
	}
	return nil
}

func syncVirtualResourceMetadata(ctx context.Context, userCred mcclient.TokenCredential, model IVirtualResourceMetadataSetter, remote cloudprovider.IVirtualResource) error {
	sysTags := remote.GetSysTags()
	sysStore := make(map[string]string, 0)
	for key, value := range sysTags {
		if key == apis.IS_SYSTEM && value == "true" {
			model.SetSystemInfo(true)
		}
		sysStore[db.SYS_CLOUD_TAG_PREFIX+key] = value
	}
	extProjectId := remote.GetProjectId()
	if len(extProjectId) > 0 {
		extProject, err := ExternalProjectManager.GetProject(extProjectId, model.GetCloudproviderId())
		if err != nil {
			log.Errorf("sync project metadata for %s %s error: %v", model.Keyword(), model.GetName(), err)
		} else {
			sysStore[db.SYS_CLOUD_TAG_PREFIX+"project"] = extProject.Name
		}
	}

	model.SetSysCloudMetadataAll(ctx, sysStore, userCred)

	tags, err := remote.GetTags()
	if err != nil {
		return err
	}

	store := make(map[string]string, 0)
	if guest, isOk := model.(*SGuest); isOk {
		//保留userTag
		userTag, _ := guest.GetAllUserMetadata()
		//获取密码
		if pwd, exist := tags["Password"]; exist {
			info := make(map[string]interface{})
			secret, _ := utils.EncryptAESBase64(guest.Id, pwd)
			info["login_account"] = guest.GetDriver().GetDefaultAccount(guest.GetOS(), "", "")
			info["login_key"] = secret
			info["login_key_timestamp"] = timeutils.UtcNow()
			guest.SetAllMetadata(ctx, info, userCred)
			delete(tags, "Password")
			remote.SetTags(tags, true)
		}
		for key, value := range userTag {
			store[db.USER_TAG_PREFIX+key] = value
		}
	}
	for key, value := range tags {
		store[db.CLOUD_TAG_PREFIX+key] = value
	}
	model.SetCloudMetadataAll(ctx, store, userCred)

	return nil
}

func SyncMetadata(ctx context.Context, userCred mcclient.TokenCredential, model IMetadataSetter, remote cloudprovider.ICloudResource) error {
	return syncMetadata(ctx, userCred, model, remote)
}

func SyncVirtualResourceMetadata(ctx context.Context, userCred mcclient.TokenCredential, model IVirtualResourceMetadataSetter, remote cloudprovider.IVirtualResource) error {
	return syncVirtualResourceMetadata(ctx, userCred, model, remote)
}
