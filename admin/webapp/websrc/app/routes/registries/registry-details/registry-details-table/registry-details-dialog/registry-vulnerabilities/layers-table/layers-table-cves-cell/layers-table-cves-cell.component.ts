import { ChangeDetectionStrategy, Component } from '@angular/core';
import { ICellRendererAngularComp } from 'ag-grid-angular';
import { ICellRendererParams } from 'ag-grid-community';

@Component({
  selector: 'app-layers-table-cves-cell',
  templateUrl: './layers-table-cves-cell.component.html',
  styleUrls: ['./layers-table-cves-cell.component.scss'],
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class LayersTableCvesCellComponent implements ICellRendererAngularComp {
  params!: ICellRendererParams;
  critical!: number;
  high!: number;
  medium!: number;

  agInit(params: ICellRendererParams): void {
    this.params = params;
    const cves = this.getCVES(params);
    this.critical = cves.critical;
    this.high = cves.high;
    this.medium = cves.medium;
  }

  refresh(params: ICellRendererParams): boolean {
    return false;
  }

  getCVES(params: ICellRendererParams): { critical: number; high: number; medium: number } {
    let critical = 0;
    let high = 0;
    let medium = 0;
    for (const vulnerability of params.node.data.vulnerabilities) {
      if (vulnerability.severity === 'Critical') {
        critical++;
      }
      if (vulnerability.severity === 'High') {
        high++;
      }
      if (vulnerability.severity === 'Medium') {
        medium++;
      }
    }
    return { critical, high, medium };
  }
}
