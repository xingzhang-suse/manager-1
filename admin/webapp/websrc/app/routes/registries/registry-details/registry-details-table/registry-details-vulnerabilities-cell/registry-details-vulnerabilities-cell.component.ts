import { ChangeDetectionStrategy, Component } from '@angular/core';
import { ICellRendererAngularComp } from 'ag-grid-angular';
import { ICellRendererParams } from 'ag-grid-community';

@Component({
  selector: 'app-vulnerabilities-cell',
  templateUrl: './registry-details-vulnerabilities-cell.component.html',
  styleUrls: ['./registry-details-vulnerabilities-cell.component.scss'],
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class RegistryDetailsVulnerabilitiesCellComponent
  implements ICellRendererAngularComp
{
  params!: ICellRendererParams;
  critical!: string;
  high!: string;
  medium!: string;

  agInit(params: ICellRendererParams): void {
    this.params = params;
    this.critical = params && params.node.data ? params.node.data.critical : 0;
    this.high = params && params.node.data ? params.node.data.high : 0;
    this.medium = params && params.node.data ? params.node.data.medium : 0;
  }

  refresh(params: ICellRendererParams): boolean {
    return false;
  }
}
