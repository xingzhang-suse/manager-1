// Generated by ScalaTS 0.5.9: https://scala-ts.github.io/scala-ts/

import { Array, isArray } from './Array';

export interface ResponseRule {
  id?: number;
  event?: string;
  comment?: string;
  group?: string;
  conditions?: Array;
  actions?: Array;
  webhooks?: Array;
  disable?: boolean;
  cfg_type?: string;
}

export function isResponseRule(v: any): v is ResponseRule {
  return (
    (!v['id'] || typeof v['id'] === 'number') &&
    (!v['event'] || typeof v['event'] === 'string') &&
    (!v['comment'] || typeof v['comment'] === 'string') &&
    (!v['group'] || typeof v['group'] === 'string') &&
    (!v['conditions'] || (v['conditions'] && isArray(v['conditions']))) &&
    (!v['actions'] || (v['actions'] && isArray(v['actions']))) &&
    (!v['webhooks'] || (v['webhooks'] && isArray(v['webhooks']))) &&
    (!v['disable'] || typeof v['disable'] === 'boolean') &&
    (!v['cfg_type'] || typeof v['cfg_type'] === 'string')
  );
}
