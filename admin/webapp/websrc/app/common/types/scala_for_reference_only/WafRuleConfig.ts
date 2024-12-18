// Generated by ScalaTS 0.5.9: https://scala-ts.github.io/scala-ts/

import { Pattern, isPattern } from './Pattern';

export interface WafRuleConfig {
  name: string;
  patterns: ReadonlyArray<Pattern>;
}

export function isWafRuleConfig(v: any): v is WafRuleConfig {
  return (
    typeof v['name'] === 'string' &&
    Array.isArray(v['patterns']) &&
    v['patterns'].every(elmt => elmt && isPattern(elmt))
  );
}
