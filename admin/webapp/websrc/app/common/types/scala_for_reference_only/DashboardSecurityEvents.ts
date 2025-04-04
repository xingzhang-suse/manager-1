// Generated by ScalaTS 0.5.9: https://scala-ts.github.io/scala-ts/

import { Array, isArray } from './Array';
import { Error, isError } from './Error';

export interface DashboardSecurityEvents {
  threats?: Array;
  violations?: Array;
  incidents?: Array;
  error?: Error;
}

export function isDashboardSecurityEvents(
  v: any
): v is DashboardSecurityEvents {
  return (
    (!v['threats'] || (v['threats'] && isArray(v['threats']))) &&
    (!v['violations'] || (v['violations'] && isArray(v['violations']))) &&
    (!v['incidents'] || (v['incidents'] && isArray(v['incidents']))) &&
    (!v['error'] || (v['error'] && isError(v['error'])))
  );
}
