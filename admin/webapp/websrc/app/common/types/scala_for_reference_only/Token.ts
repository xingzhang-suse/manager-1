// Generated by ScalaTS 0.5.9: https://scala-ts.github.io/scala-ts/

import { Array, isArray } from './Array';

export interface Token {
  token: string;
  fullname: string;
  server: string;
  username: string;
  email?: string;
  role: string;
  locale: string;
  timeout?: number;
  default_password: boolean;
  modify_password: boolean;
  role_domains?: { [key: string]: Array };
}

export function isToken(v: any): v is Token {
  return (
    typeof v['token'] === 'string' &&
    typeof v['fullname'] === 'string' &&
    typeof v['server'] === 'string' &&
    typeof v['username'] === 'string' &&
    (!v['email'] || typeof v['email'] === 'string') &&
    typeof v['role'] === 'string' &&
    typeof v['locale'] === 'string' &&
    (!v['timeout'] || typeof v['timeout'] === 'number') &&
    typeof v['default_password'] === 'boolean' &&
    typeof v['modify_password'] === 'boolean' &&
    (!v['role_domains'] ||
      (typeof v['role_domains'] == 'object' &&
        Object.keys(v['role_domains']).every(
          key =>
            typeof key === 'string' &&
            v['role_domains'][key] &&
            isArray(v['role_domains'][key])
        )))
  );
}
