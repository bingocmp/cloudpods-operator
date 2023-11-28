package component

import (
	"yunion.io/x/onecloud/pkg/generalservice/options"

	"yunion.io/x/onecloud-operator/pkg/apis/constants"
	"yunion.io/x/onecloud-operator/pkg/apis/onecloud/v1alpha1"
	"yunion.io/x/onecloud-operator/pkg/controller"
	"yunion.io/x/onecloud-operator/pkg/util/option"
)

func init() {
	RegisterComponent(NewGeneralService())
}

type generalService struct {
	*baseService
}

func NewGeneralService() Component {
	return &generalService{
		baseService: newBaseService(v1alpha1.GeneralServiceComponentType, new(options.SGeneralServiceOptions)),
	}
}
func (r generalService) BuildClusterConfigDB(clsCfg *v1alpha1.OnecloudClusterConfig, db v1alpha1.DBConfig) error {
	clsCfg.GeneralService.DB = db
	return nil
}

func (r generalService) BuildClusterConfigCloudUser(clsCfg *v1alpha1.OnecloudClusterConfig, user v1alpha1.CloudUser) error {
	clsCfg.GeneralService.CloudUser = user
	return nil
}

func (r generalService) GetDefaultDBConfig(cfg *v1alpha1.OnecloudClusterConfig) *v1alpha1.DBConfig {
	return &cfg.GeneralService.DB
}

func (r generalService) GetDefaultClickhouseConfig(cfg *v1alpha1.OnecloudClusterConfig) *v1alpha1.DBConfig {
	return &cfg.GeneralService.ClickhouseConf
}

func (r generalService) GetDefaultCloudUser(cfg *v1alpha1.OnecloudClusterConfig) *v1alpha1.CloudUser {
	return &cfg.GeneralService.CloudUser
}

func (r generalService) GetConfig(oc *v1alpha1.OnecloudCluster, cfg *v1alpha1.OnecloudClusterConfig) (interface{}, error) {
	opt := &options.Options
	if err := option.SetOptionsDefault(opt, constants.ServiceTypeGeneralService); err != nil {
		return nil, err
	}
	config := cfg.GeneralService
	option.SetDBOptions(&opt.DBOptions, oc.Spec.Mysql, config.DB)
	option.SetClickhouseOptions(&opt.DBOptions, oc.Spec.Clickhouse, config.ClickhouseConf)
	option.SetOptionsServiceTLS(&opt.BaseOptions, false)
	option.SetServiceCommonOptions(&opt.CommonOptions, oc, config.ServiceCommonOptions)
	opt.Port = config.Port
	return opt, nil
}
func (r generalService) GetPhaseControl(man controller.ComponentManager) controller.PhaseControl {
	return controller.NewRegisterEndpointComponent(man, v1alpha1.GeneralServiceComponentType,
		constants.ServiceNameGeneralService, constants.ServiceTypeGeneralService,
		man.GetCluster().Spec.GeneralService.Service.NodePort, "")
}
