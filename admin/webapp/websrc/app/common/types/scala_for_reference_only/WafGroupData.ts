// Generated by ScalaTS 0.5.9: https://scala-ts.github.io/scala-ts/

import { WafGroup, isWafGroup } from './WafGroup';

export interface WafGroupData {
  waf_group: WafGroup;
}

export function isWafGroupData(v: any): v is WafGroupData {
  return v['waf_group'] && isWafGroup(v['waf_group']);
}
