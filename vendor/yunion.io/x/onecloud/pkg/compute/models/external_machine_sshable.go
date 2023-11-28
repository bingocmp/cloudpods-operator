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
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	api "yunion.io/x/cloudmux/pkg/apis/compute"
	"yunion.io/x/cloudmux/pkg/cloudprovider"
	"yunion.io/x/jsonutils"
	"yunion.io/x/log"
	"yunion.io/x/pkg/errors"
	"yunion.io/x/pkg/tristate"

	compute_api "yunion.io/x/onecloud/pkg/apis/compute"
	"yunion.io/x/onecloud/pkg/cloudcommon/db"
	"yunion.io/x/onecloud/pkg/compute/sshkeys"
	"yunion.io/x/onecloud/pkg/httperrors"
	"yunion.io/x/onecloud/pkg/mcclient"
	"yunion.io/x/onecloud/pkg/mcclient/auth"
	ansible_modules "yunion.io/x/onecloud/pkg/mcclient/modules/ansible"
	"yunion.io/x/onecloud/pkg/util/ansible"
	ssh_util "yunion.io/x/onecloud/pkg/util/ssh"
)

type ExternalMachineSshableTryData struct {
	DryRun bool

	User       string
	Host       string
	Port       int
	PrivateKey string
	PublicKey  string

	MethodTried []compute_api.ExternalMachineSshableMethodData
}

func (tryData *ExternalMachineSshableTryData) AddMethodTried(tryMethodData compute_api.ExternalMachineSshableMethodData) {
	tryData.MethodTried = append(tryData.MethodTried, tryMethodData)
}

func (tryData *ExternalMachineSshableTryData) outputJSON() jsonutils.JSONObject {
	out := compute_api.ExternalMachineSshableOutput{
		User:      tryData.User,
		PublicKey: tryData.PublicKey,

		MethodTried: tryData.MethodTried,
	}
	outJSON := jsonutils.Marshal(out)
	return outJSON
}

//func (em *SExternalMachine) winrmTryEach(ctx context.Context, userCred mcclient.TokenCredential, tryData *ExternalMachineSshableTryData) error {
//	methodData := compute_api.ExternalMachineSshableMethodData{
//		Method: compute_api.MethodDirect,
//		Host:   em.IpAddr,
//		Port:   tryData.Port,
//	}
//
//	endpoint := winrm.NewEndpoint(tryData.Host, tryData.Port, false, false, nil, nil, nil, time.Second*7)
//	if client, err := winrm.NewClient(endpoint, compute_api.VM_DEFAULT_WINDOWS_LOGIN_USER, em.Password); err == nil {
//		ctx, cancel := context.WithCancel(context.Background())
//		defer cancel()
//		if _, err = client.RunWithContext(ctx, "ipconfig /all", os.Stdout, os.Stderr); err != nil {
//			methodData.Reason = errors.Wrap(err, "winrm unable to run").Error()
//		} else {
//			methodData.Sshable = true
//		}
//	} else {
//		methodData.Reason = errors.Wrap(err, "winrm unable to connect").Error()
//		return err
//	}
//	tryData.AddMethodTried(methodData)
//
//	return nil
//}

//func (em *SExternalMachine) GetDetailsWinrm(ctx context.Context, userCred mcclient.TokenCredential, query jsonutils.JSONObject) (jsonutils.JSONObject, error) {
//	tryData := &ExternalMachineSshableTryData{
//		User: em.UserName,
//		Host: em.IpAddr,
//		Port: em.Port,
//	}
//	if err := em.winrmTryEach(ctx, userCred, tryData); err != nil {
//		return nil, err
//	}
//	{
//		sshable := false
//		for i := range tryData.MethodTried {
//			if tryData.MethodTried[i].Sshable {
//				sshable = true
//				break
//			}
//		}
//		if _, err := db.Update(em, func() error {
//			if tristate.NewFromBool(sshable).IsTrue() {
//				em.Status = api.VM_RUNNING
//			} else {
//				em.Status = api.VM_UNKNOWN
//			}
//			return nil
//		}); err != nil {
//			log.Errorf("update ExternalMachine %s(%s) winrm_last_state to %v: %v", em.Name, em.Id, sshable, err)
//		}
//	}
//
//	return tryData.outputJSON(), nil
//}

func (em *SExternalMachine) GetDetailsSshable(ctx context.Context, userCred mcclient.TokenCredential, query jsonutils.JSONObject) (jsonutils.JSONObject, error) {
	tryData := &ExternalMachineSshableTryData{
		User: "cloudroot",
		Host: em.IpAddr,
		Port: em.Port,
	}

	// - get admin key
	privateKey, publicKey, err := sshkeys.GetSshAdminKeypair(ctx)
	if err != nil {
		return nil, httperrors.NewInternalServerError("fetch ssh private key: %v", err)
	}
	tryData.PrivateKey = privateKey
	tryData.PublicKey = publicKey
	if err := em.sshableTryEach(ctx, userCred, tryData); err != nil {
		return nil, err
	}

	{
		sshable := false
		for i := range tryData.MethodTried {
			if tryData.MethodTried[i].Sshable {
				sshable = true
				break
			}
		}
		if _, err := db.Update(em, func() error {
			if tristate.NewFromBool(sshable).IsTrue() {
				em.Status = api.VM_RUNNING
			} else {
				em.Status = api.VM_UNKNOWN
			}
			return nil
		}); err != nil {
			log.Errorf("update ExternalMachine %s(%s) sshable_last_state to %v: %v", em.Name, em.Id, sshable, err)
		}
	}

	return tryData.outputJSON(), nil
}

func (em *SExternalMachine) sshableTryEach(ctx context.Context, userCred mcclient.TokenCredential, tryData *ExternalMachineSshableTryData) error {
	// make sure the ssh port
	var sshPort int
	if tryData.Port != 0 {
		sshPort = tryData.Port
	} else {
		sshPort = em.GetSshPort(ctx, userCred)
	}
	tryData.Port = sshPort
	//   - check ip
	if ok := em.sshableTryIp(ctx, tryData); ok {
		return nil
	}
	return nil
}

func (em *SExternalMachine) sshableTryIp(ctx context.Context, tryData *ExternalMachineSshableTryData) bool {
	methodData := compute_api.ExternalMachineSshableMethodData{
		Method: compute_api.MethodDirect,
		Host:   em.IpAddr,
		Port:   tryData.Port,
	}
	return em.sshableTry(ctx, tryData, methodData)
}

func (em *SExternalMachine) sshableTry(ctx context.Context, tryData *ExternalMachineSshableTryData, methodData compute_api.ExternalMachineSshableMethodData) bool {
	if tryData.DryRun {
		tryData.AddMethodTried(methodData)
		return true
	}
	ctx, _ = context.WithTimeout(ctx, 7*time.Second)
	conf := ssh_util.ClientConfig{
		Username:   tryData.User,
		Host:       methodData.Host,
		Port:       methodData.Port,
		PrivateKey: tryData.PrivateKey,
	}
	ok := false
	if client, err := conf.ConnectContext(ctx); err == nil {
		defer client.Close()
		methodData.Sshable = true
		ok = true
	} else {
		methodData.Reason = err.Error()
	}
	tryData.AddMethodTried(methodData)
	return ok
}

func (em *SExternalMachine) PerformExec(ctx context.Context, userCred mcclient.TokenCredential, query jsonutils.JSONObject, input compute_api.ExternalMachineHaveORFSInput) (compute_api.ExternalMachineHaveORFSOutput, error) {
	var output compute_api.ExternalMachineHaveORFSOutput
	v := em.GetMetadata(ctx, "__orfs", userCred)
	if v == "true" {
		output.Have = true
		return output, nil
	}
	v = em.GetMetadata(ctx, "sys:orfs", userCred)
	if v == "true" {
		output.Have = true
		return output, nil
	}
	return output, nil
}

func (manager *SExternalMachineManager) PerformMakeSshable(ctx context.Context, userCred mcclient.TokenCredential, query jsonutils.JSONObject, input compute_api.ExternalMachineMakeSshableInput) (output compute_api.ExternalMachineMakeSshableOutput, err error) {
	externalMachine := &SExternalMachine{}
	externalMachine.IpAddr = input.IpAddr
	externalMachine.ProjectId = userCred.GetProjectId()
	return externalMachine.PerformMakeSshable(ctx, userCred, query, input)
}

func (em *SExternalMachine) PerformMakeSshable(ctx context.Context, userCred mcclient.TokenCredential, query jsonutils.JSONObject, input compute_api.ExternalMachineMakeSshableInput) (output compute_api.ExternalMachineMakeSshableOutput, err error) {
	if input.User == "" {
		input.User = em.UserName
	}
	if input.Password == "" {
		input.Password = em.Password
	}
	if input.Port == 0 {
		input.Port = em.Port
	}
	if input.PrivateKey == "" && input.Password == "" {
		return output, httperrors.NewBadRequestError("private_key and password cannot both be empty")
	}

	_, projectPublicKey, err := sshkeys.GetSshProjectKeypair(ctx, em.ProjectId)
	if err != nil {
		return output, httperrors.NewInternalServerError("fetch project public key: %v", err)
	}
	_, adminPublicKey, err := sshkeys.GetSshAdminKeypair(ctx)
	if err != nil {
		return output, httperrors.NewInternalServerError("fetch admin public key: %v", err)
	}

	tryData := &ExternalMachineSshableTryData{
		DryRun: true,
		Port:   input.Port,
	}
	if err := em.sshableTryEach(ctx, userCred, tryData); err != nil {
		return output, httperrors.NewNotAcceptableError("searching for usable ssh address: %v", err)
	} else if len(tryData.MethodTried) == 0 {
		return output, httperrors.NewNotAcceptableError("no usable ssh address")
	}

	err = cloudprovider.Wait(time.Second*5, time.Minute*2, func() (bool, error) {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(tryData.MethodTried[0].Host, fmt.Sprintf("%d", tryData.MethodTried[0].Port)), time.Second)
		if err != nil {
			return true, err
		}
		if conn != nil {
			conn.Close()
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return output, httperrors.NewInternalServerError("ssh port unable to connect")
	}

	// storage sshport
	if input.Port != 0 && !input.DryRun {
		err := em.SetSshPort(ctx, userCred, input.Port)
		if err != nil {
			return output, errors.Wrap(err, "unable to set sshport for ExternalMachine")
		}
	}
	host := ansible.Host{
		Name: em.IpAddr,
	}
	host.SetVar("ansible_user", input.User)
	host.SetVar("ansible_host", tryData.MethodTried[0].Host)
	host.SetVar("ansible_port", fmt.Sprintf("%d", tryData.MethodTried[0].Port))
	host.SetVar("ansible_become", "yes")

	pb := &ansible.Playbook{
		Inventory: ansible.Inventory{
			Hosts: []ansible.Host{host},
		},
		Modules: []ansible.Module{
			{
				Name: "group",
				Args: []string{
					"name=cloudroot",
					"state=present",
				},
			},
			{
				Name: "user",
				Args: []string{
					"name=cloudroot",
					"state=present",
					"group=cloudroot",
				},
			},
			{
				Name: "authorized_key",
				Args: []string{
					"user=cloudroot",
					"state=present",
					fmt.Sprintf("key=%q", adminPublicKey),
				},
			},
			{
				Name: "authorized_key",
				Args: []string{
					"user=cloudroot",
					"state=present",
					fmt.Sprintf("key=%q", projectPublicKey),
				},
			},
			{
				Name: "lineinfile",
				Args: []string{
					"dest=/etc/sudoers",
					"state=present",
					fmt.Sprintf("regexp=%q", "^cloudroot "),
					fmt.Sprintf("line=%q", "cloudroot ALL=(ALL) NOPASSWD: ALL"),
					fmt.Sprintf("validate=%q", "visudo -cf %s"),
				},
			},
		},
	}
	if input.PrivateKey != "" {
		pb.PrivateKey = []byte(input.PrivateKey)
	} else if input.Password != "" {
		host.SetVar("ansible_password", input.Password)
	}

	cliSess := auth.GetSession(ctx, userCred, "")
	pbId := ""
	pbName := "make-sshable-" + em.IpAddr
	pbModel, err := ansible_modules.AnsiblePlaybooks.UpdateOrCreatePbModel(
		ctx, cliSess, pbId, pbName, pb,
	)
	if err != nil {
		return output, httperrors.NewGeneralError(err)
	}

	output = compute_api.ExternalMachineMakeSshableOutput{
		AnsiblePlaybookId: pbModel.Id,
	}
	return output, nil
}

func (em *SExternalMachine) GetDetailsMakeSshableCmd(ctx context.Context, userCred mcclient.TokenCredential, query jsonutils.JSONObject) (output compute_api.ExternalMachineMakeSshableCmdOutput, err error) {
	_, projectPublicKey, err := sshkeys.GetSshProjectKeypair(ctx, em.ProjectId)
	if err != nil {
		return output, httperrors.NewInternalServerError("fetch project public key: %v", err)
	}
	_, adminPublicKey, err := sshkeys.GetSshAdminKeypair(ctx)
	if err != nil {
		return output, httperrors.NewInternalServerError("fetch admin public key: %v", err)
	}

	varVals := [][2]string{
		{"user", "cloudroot"},
		{"adminpub", strings.TrimSpace(adminPublicKey)},
		{"projpub", strings.TrimSpace(projectPublicKey)},
	}
	shellCmd := ""
	for i := range varVals {
		varVal := varVals[i]
		shellCmd += fmt.Sprintf("%s=%q\n", varVal[0], varVal[1])
	}

	shellCmd += `
group="$user"
sshdir="/home/$user/.ssh"
keyfile="$sshdir/authorized_keys"
`
	shellCmd += `
id -g "$group" &>/dev/null || groupadd "$group"
id -u "$user"  &>/dev/null || useradd --create-home --gid "$group" "$user"
mkdir -p "$sshdir"
grep -q -F "$adminpub" "$keyfile" &>/dev/null || echo "$adminpub" >>"$keyfile"
grep -q -F "$projpub" "$keyfile"  &>/dev/null || echo "$projpub" >>"$keyfile"
chown -R "$user:$group" "$sshdir"
chmod -R 700 "$sshdir"
chmod -R 600 "$keyfile"

if ! grep -q "^$user " /etc/sudoers; then
  echo "$user ALL=(ALL) NOPASSWD: ALL" | EDITOR='tee -a' visudo
fi
`
	output = compute_api.ExternalMachineMakeSshableCmdOutput{
		ShellCmd: shellCmd,
	}
	return output, nil
}

func (em *SExternalMachine) GetSshPort(ctx context.Context, userCred mcclient.TokenCredential) int {
	portStr := em.GetMetadata(ctx, compute_api.SSH_PORT, userCred)
	if portStr == "" {
		return 22
	}
	port, _ := strconv.Atoi(portStr)
	return port
}

func (em *SExternalMachine) SetSshPort(ctx context.Context, userCred mcclient.TokenCredential, port int) error {
	return em.SetMetadata(ctx, compute_api.SSH_PORT, port, userCred)
}

func (em *SExternalMachine) PerformSetSshport(ctx context.Context, userCred mcclient.TokenCredential, query jsonutils.JSONObject, input compute_api.ExternalMachineSetSshportInput) (jsonutils.JSONObject, error) {
	if input.Port < 0 {
		return nil, httperrors.NewInputParameterError("invalid port")
	}
	return nil, em.SetSshPort(ctx, userCred, input.Port)
}

func (em *SExternalMachine) GetDetailsSshport(ctx context.Context, userCred mcclient.TokenCredential, query jsonutils.JSONObject) (compute_api.ExternalMachineSshportOutput, error) {
	port := em.GetSshPort(ctx, userCred)
	return compute_api.ExternalMachineSshportOutput{Port: port}, nil
}
