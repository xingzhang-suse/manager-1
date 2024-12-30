import {
  Component,
  OnInit,
  HostListener,
  ChangeDetectorRef,
  ViewChild,
} from '@angular/core';
import { GlobalConstant } from '@common/constants/global.constant';
import { GlobalVariable } from '@common/variables/global.variable';
import { GroupsComponent } from '@components/groups/groups.component';
import { FederatedConfigurationService } from '@services/federated-configuration.service';
import { FormControl } from '@angular/forms';
import { AuthUtilsService } from '@common/utils/auth.utils';

export const fedGroupDetailsTabs = [
  'process profile rules',
  'file access rules',
  'DLP',
  'WAF',
];

@Component({
  selector: 'app-federated-policy',
  templateUrl: './federated-policy.component.html',
  styleUrls: ['./federated-policy.component.scss'],
})
export class FederatedPolicyComponent implements OnInit {
  public activeTabIndex: number = 0;
  public navSource: string = '';
  public navSource4Group: string = '';
  public CFG_TYPE: any = GlobalConstant.CFG_TYPE;
  public height: number = 0;
  public editGroupSensorModal: any;
  public toggleWAFConfigEnablement: any;
  public toggleDLPConfigEnablement: any;
  public showPredefinedRules: any;
  public enabled: boolean;
  public removeProfile: any;
  public editProfile: any;
  public addProfile: any;
  public isWriteWafAuthorized: boolean;
  public isWriteDlpAuthorized: boolean;
  public isWriteGroupAuthorized: boolean;
  public isWriteFileAccessRuleAuthorized: boolean;
  public isWriteProcessProfileRuleAuthorized: boolean;
  public selectedFileAccessRules: any;
  public selectedProcessProfileRules: any;
  public filter = new FormControl('');
  private readonly win: any;
  get activeTab(): string {
    return fedGroupDetailsTabs[
      this.federatedConfigurationService.activeTabIndex4Group
    ];
  }
  @ViewChild(GroupsComponent) groupsView!: GroupsComponent;

  constructor(
    public federatedConfigurationService: FederatedConfigurationService,
    private authUtilsService: AuthUtilsService,
    private cd: ChangeDetectorRef
  ) {
    this.win = GlobalVariable.window;
  }

  @HostListener('window:resize', ['$event'])
  onResize(event) {
    this.height = this.setHeight(event.target.innerHeight);
  }

  ngOnInit(): void {
    this.activeTabIndex = 0;
    this.isWriteGroupAuthorized =
      this.authUtilsService.getDisplayFlag('write_group') &&
      this.authUtilsService.getDisplayFlag('multi_cluster_w');
    this.isWriteWafAuthorized =
      this.authUtilsService.getDisplayFlag('write_waf_rule') &&
      this.authUtilsService.getDisplayFlag('multi_cluster_w');
    this.isWriteDlpAuthorized =
      this.authUtilsService.getDisplayFlag('write_dlp_rule') &&
      this.authUtilsService.getDisplayFlag('multi_cluster_w');
    this.height = this.setHeight(this.win.innerHeight);
    this.navSource = GlobalConstant.NAV_SOURCE.FED_POLICY;
    this.navSource4Group = GlobalConstant.NAV_SOURCE.GROUP;
  }

  ngAfterViewInit() {
    this.cd.detectChanges();
  }

  activateTab(event) {
    this.activeTabIndex = event.index;
  }

  private setHeight = (innerHeight: number) => {
    return (innerHeight - 210) / 2;
  };

  getStatus = enabled => {
    this.enabled = enabled;
  };

  isIncludingGroundRule = () => {
    let index = this.selectedProcessProfileRules.findIndex(
      rule => rule.cfg_type === GlobalConstant.CFG_TYPE.GROUND
    );
    return index > -1;
  };

  getEditGroupSensorModal = editGroupSensorModal => {
    this.editGroupSensorModal = editGroupSensorModal;
  };

  getToggleWAFConfigEnablement = toggleWAFConfigEnablement => {
    this.toggleWAFConfigEnablement = toggleWAFConfigEnablement;
  };

  getToggleDLPConfigEnablement = toggleDLPConfigEnablement => {
    this.toggleDLPConfigEnablement = toggleDLPConfigEnablement;
  };

  getSelectedFileAccessRules = selectedFileAccessRules => {
    this.selectedFileAccessRules = selectedFileAccessRules;
  };

  getSelectedProcessProfileRules = selectedProcessProfileRules => {
    this.selectedProcessProfileRules = selectedProcessProfileRules;
  };

  getRemoveProfile = removeProfile => {
    this.removeProfile = removeProfile;
  };

  getEditProfile = editProfile => {
    this.editProfile = editProfile;
  };

  getAddProfile = addProfile => {
    this.addProfile = addProfile;
  };

  getShowPredefinedRules = showPredefinedRules => {
    this.showPredefinedRules = showPredefinedRules;
  };

  activateTab4Group = event => {
    this.federatedConfigurationService.activeTabIndex4Group = event.index;
  };
}
