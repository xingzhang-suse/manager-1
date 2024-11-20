import { Component, OnInit, Input, SecurityContext } from '@angular/core';
import { TranslateService } from '@ngx-translate/core';
import { CapitalizePipe } from '@common/pipes/app.pipes';
import { DomSanitizer } from '@angular/platform-browser';
import { ChartConfiguration } from 'chart.js';

@Component({
  selector: 'app-top-vulnerable-assets-chart',
  templateUrl: './top-vulnerable-assets-chart.component.html',
  styleUrls: ['./top-vulnerable-assets-chart.component.scss'],
})
export class TopVulnerableAssetsChartComponent implements OnInit {
  @Input() highPriorityVulnerabilities: any;
  @Input() assetType: string;
  @Input() isReport: boolean = false;
  @Input() isAutoScanOff: boolean = false;
  topVulnerableAssetsBarChartConfig: ChartConfiguration<
    'bar',
    number[],
    string
  >;
  noChartData: boolean = false;

  constructor(
    private translate: TranslateService,
    private sanitizer: DomSanitizer,
    private capitalizePipe: CapitalizePipe
  ) {}

  ngOnInit(): void {
    this.drawTopVulnerableAssetsBarChart(
      this.highPriorityVulnerabilities,
      this.assetType
    );
  }

  drawTopVulnerableAssetsBarChart = (
    highPriorityVulnerabilities: any,
    assetType: string
  ) => {
    let topVulnerableAssetsLabel: Array<string> = new Array(5);
    let topCriticalVulnerableAssetsData: Array<number> = new Array(5);
    let topHighVulnerableAssetsData: Array<number> = new Array(5);
    let topMediumVulnerableAssetsData: Array<number> = new Array(5);
    topVulnerableAssetsLabel.fill('');
    topCriticalVulnerableAssetsData.fill(0);
    topHighVulnerableAssetsData.fill(0);
    topMediumVulnerableAssetsData.fill(0);
    highPriorityVulnerabilities[assetType][
      `top5${this.capitalizePipe.transform(assetType)}`
    ].forEach((asset, index) => {
      if (assetType === 'containers') {
        topVulnerableAssetsLabel[index] = this.sanitizer.sanitize(
          SecurityContext.HTML,
          asset.display_name
        )!;
        topCriticalVulnerableAssetsData[index] = asset.critical4Dashboard;
        topHighVulnerableAssetsData[index] = asset.high4Dashboard;
        topMediumVulnerableAssetsData[index] = asset.medium4Dashboard;
      } else {
        topVulnerableAssetsLabel[index] = this.sanitizer.sanitize(
          SecurityContext.HTML,
          asset.name
        )!;
        topCriticalVulnerableAssetsData[index] = asset.scan_summary.critical;
        topHighVulnerableAssetsData[index] = asset.scan_summary.high;
        topMediumVulnerableAssetsData[index] = asset.scan_summary.medium;
      }
    });

    this.noChartData =
      topCriticalVulnerableAssetsData.reduce((prev, curr) => prev + curr) ===
        0 &&
      topHighVulnerableAssetsData.reduce((prev, curr) => prev + curr) === 0 &&
      topMediumVulnerableAssetsData.reduce((prev, curr) => prev + curr) === 0;

    this.topVulnerableAssetsBarChartConfig = {
      options: {
        animation: false,
        indexAxis: 'y',
        scales: {
          x: {
            ticks: {
              callback: (value: any) => {
                if (value % 1 === 0) {
                  return value;
                }
              },
            },
            beginAtZero: true,
          },
          y: {
            ticks: {
              crossAlign: 'far',
              callback: function (value, index, values): string {
                let label = this.getLabelForValue(value as number);
                return label.length > 22
                  ? `${label.substring(0, 22)}...`
                  : label;
              },
            },
          },
        },
        maintainAspectRatio: false,
        plugins: {
          title: {
            display: false,
            text: `Top Vulnerable ${this.capitalizePipe.transform(assetType)}`,
          },
          legend: {
            display: true,
            position: 'top',
          },
        },
      },
      data: {
        labels: topVulnerableAssetsLabel,
        datasets: [
          {
            data: topCriticalVulnerableAssetsData,
            label: this.translate.instant('enum.CRITICAL'),
            backgroundColor: 'rgba(233, 30, 99, 0.3)',
            borderColor: '#e91e63',
            hoverBackgroundColor: 'rgba(233, 30, 99, 0.3)',
            hoverBorderColor: '#e91e63',
            barThickness: 8,
            borderWidth: 2,
          },
          {
            data: topHighVulnerableAssetsData,
            label: this.translate.instant('enum.HIGH'),
            backgroundColor: 'rgba(239, 83, 80, 0.3)',
            borderColor: '#ef5350',
            hoverBackgroundColor: 'rgba(239, 83, 80, 0.3)',
            hoverBorderColor: '#ef5350',
            barThickness: 8,
            borderWidth: 2,
          },
          {
            data: topMediumVulnerableAssetsData,
            label: this.translate.instant('enum.MEDIUM'),
            backgroundColor: 'rgba(255, 152, 0, 0.3)',
            borderColor: '#ff9800',
            hoverBackgroundColor: 'rgba(255, 152, 0, 0.3)',
            hoverBorderColor: '#ff9800',
            barThickness: 8,
            borderWidth: 2,
          },
        ],
      },
      type: 'bar',
    };
  };
}
