import { TestBed } from '@angular/core/testing';
import { TranslateModule } from '@ngx-translate/core';

import { VulnerabilitiesFilterService } from './vulnerabilities.filter.service';

describe('VulnerabilitiesFilterService', () => {
  let service: VulnerabilitiesFilterService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [TranslateModule.forRoot()],
      providers: [VulnerabilitiesFilterService],
    });
    service = TestBed.inject(VulnerabilitiesFilterService);
  });

  it('should filter vulnerabilities by selected view', () => {
    const vulnerabilities = [
      { workloads: [{ id: 'w1' }], nodes: [], platforms: [], images: [] },
      { workloads: [], nodes: [{ id: 'n1' }], platforms: [], images: [] },
      { workloads: [], nodes: [], platforms: [{ id: 'p1' }], images: [] },
      { workloads: [], nodes: [], platforms: [], images: [{ id: 'i1' }] },
    ] as any;

    expect(service.filterView(vulnerabilities, 'all')).toEqual(vulnerabilities);
    expect(service.filterView(vulnerabilities, 'containers')).toEqual([
      vulnerabilities[0],
    ]);
    expect(service.filterView(vulnerabilities, 'infrastructure')).toEqual([
      vulnerabilities[1],
      vulnerabilities[2],
    ]);
    expect(service.filterView(vulnerabilities, 'registry')).toEqual([
      vulnerabilities[3],
    ]);
  });
});
