import assert from 'node:assert';
import test from 'node:test';

import {
  GetDnsRecords,
  GetReverseDnsRecords,
  type dns_record_query_result_t,
  type dns_record_type_t,
  type dns_resolver_instance_i
} from '../../src/index';

type fake_resolve_behavior_t = {
  [query_key: string]: () => Promise<unknown[]>;
};

type fake_reverse_behavior_t = {
  [ip_address: string]: () => Promise<string[]>;
};

type fake_resolver_behavior_t = {
  resolve_behavior?: fake_resolve_behavior_t;
  reverse_behavior?: fake_reverse_behavior_t;
};

type fake_resolver_behavior_by_endpoint_t = {
  [resolver_endpoint: string]: fake_resolver_behavior_t;
};

class FakeResolver implements dns_resolver_instance_i {
  private resolver_endpoint = '';
  private readonly resolver_behaviors: fake_resolver_behavior_by_endpoint_t;

  constructor(params: {
    resolver_behaviors: fake_resolver_behavior_by_endpoint_t;
  }) {
    this.resolver_behaviors = params.resolver_behaviors;
  }

  setServers(servers: string[]): void {
    this.resolver_endpoint = servers[0];
  }

  async resolve(hostname: string, rrtype: dns_record_type_t): Promise<unknown[]> {
    const resolver_behavior = this.resolver_behaviors[this.resolver_endpoint];
    const behavior_function =
      resolver_behavior?.resolve_behavior?.[`${hostname}|${rrtype}`];

    if (!behavior_function) {
      return [];
    }

    return behavior_function();
  }

  async reverse(ip_address: string): Promise<string[]> {
    const resolver_behavior = this.resolver_behaviors[this.resolver_endpoint];
    const behavior_function = resolver_behavior?.reverse_behavior?.[ip_address];

    if (!behavior_function) {
      return [];
    }

    return behavior_function();
  }
}

function CreateResolverFactory(params: {
  resolver_behaviors: fake_resolver_behavior_by_endpoint_t;
}): () => dns_resolver_instance_i {
  return function BuildResolver(): dns_resolver_instance_i {
    return new FakeResolver({ resolver_behaviors: params.resolver_behaviors });
  };
}

function CreateDnsError(params: {
  error_code: string;
  error_message: string;
}): NodeJS.ErrnoException {
  const dns_error = new Error(params.error_message) as NodeJS.ErrnoException;
  dns_error.code = params.error_code;
  return dns_error;
}

function GetRecordResult(params: {
  record_results: dns_record_query_result_t[];
  record_type: string;
}): dns_record_query_result_t {
  const record_result = params.record_results.find(
    (candidate_record) => candidate_record.record_type === params.record_type
  );

  if (!record_result) {
    throw new Error(`Missing record result for type "${params.record_type}".`);
  }

  return record_result;
}

test(
  'GetDnsRecords returns resolver-grouped records for multi-resolver lookups.',
  async function () {
    const resolver_behaviors: fake_resolver_behavior_by_endpoint_t = {
      '8.8.8.8:53': {
        resolve_behavior: {
          'example.com|A': async function ResolveARecord(): Promise<unknown[]> {
            return ['93.184.216.34'];
          },
          'example.com|PTR': async function ResolvePtrFromHostname(): Promise<
            unknown[]
          > {
            return [];
          },
          '1.1.1.1|A': async function ResolveIpAsARecord(): Promise<unknown[]> {
            throw CreateDnsError({
              error_code: 'NXDOMAIN',
              error_message: 'No A record for IP input.'
            });
          }
        },
        reverse_behavior: {
          '1.1.1.1': async function ReverseIp(): Promise<string[]> {
            return ['one.one.one.one'];
          }
        }
      },
      '[2001:4860:4860::8888]:53': {
        resolve_behavior: {
          'example.com|A': async function ResolveAWithError(): Promise<
            unknown[]
          > {
            throw CreateDnsError({
              error_code: 'SERVFAIL',
              error_message: 'Server failure'
            });
          },
          'example.com|PTR': async function ResolvePtrWithEmpty(): Promise<
            unknown[]
          > {
            return [];
          },
          '1.1.1.1|A': async function ResolveIpAsAEmpty(): Promise<unknown[]> {
            return [];
          }
        },
        reverse_behavior: {
          '1.1.1.1': async function ReverseIpWithError(): Promise<string[]> {
            throw CreateDnsError({
              error_code: 'REFUSED',
              error_message: 'Refused by resolver'
            });
          }
        }
      }
    };

    const response = await GetDnsRecords(
      {
        resolvers: [
          {
            resolver_id: 'google_ipv4',
            resolver_host: '8.8.8.8',
            resolver_port: 53
          },
          '[2001:4860:4860::8888]:53'
        ],
        targets: ['example.com', '1.1.1.1'],
        record_types: ['A', 'PTR'],
        timeout_ms: 100,
        max_retries: 0,
        concurrency_limit: 4
      },
      {
        resolver_factory: CreateResolverFactory({
          resolver_behaviors
        })
      }
    );

    assert.equal(response.resolver_results.length, 2);

    const first_resolver = response.resolver_results[0];
    const first_resolver_example_target = first_resolver.target_results[0];
    const first_resolver_ip_target = first_resolver.target_results[1];

    const example_a_result = GetRecordResult({
      record_results: first_resolver_example_target.record_results,
      record_type: 'A'
    });
    const example_ptr_result = GetRecordResult({
      record_results: first_resolver_example_target.record_results,
      record_type: 'PTR'
    });
    const ip_ptr_result = GetRecordResult({
      record_results: first_resolver_ip_target.record_results,
      record_type: 'PTR'
    });

    assert.equal(first_resolver.resolver_id, 'google_ipv4');
    assert.equal(example_a_result.status, 'success');
    assert.deepEqual(example_a_result.answers, ['93.184.216.34']);
    assert.equal(example_ptr_result.status, 'empty');
    assert.equal(ip_ptr_result.status, 'success');
    assert.deepEqual(ip_ptr_result.answers, ['one.one.one.one']);

    const second_resolver = response.resolver_results[1];
    const second_resolver_example_target = second_resolver.target_results[0];
    const second_resolver_ip_target = second_resolver.target_results[1];

    const second_example_a_result = GetRecordResult({
      record_results: second_resolver_example_target.record_results,
      record_type: 'A'
    });
    const second_ip_ptr_result = GetRecordResult({
      record_results: second_resolver_ip_target.record_results,
      record_type: 'PTR'
    });

    assert.equal(second_example_a_result.status, 'error');
    assert.equal(second_example_a_result.error_code, 'SERVFAIL');
    assert.equal(second_ip_ptr_result.status, 'error');
    assert.equal(second_ip_ptr_result.error_code, 'REFUSED');
  }
);

test(
  'GetReverseDnsRecords performs PTR lookups for IPv4 and IPv6 targets.',
  async function () {
    const resolver_behaviors: fake_resolver_behavior_by_endpoint_t = {
      '1.1.1.1:53': {
        reverse_behavior: {
          '8.8.8.8': async function ReverseIpv4(): Promise<string[]> {
            return ['dns.google'];
          },
          '2001:4860:4860::8888': async function ReverseIpv6(): Promise<
            string[]
          > {
            return ['dns.google'];
          }
        }
      }
    };

    const response = await GetReverseDnsRecords(
      {
        resolvers: ['1.1.1.1:53'],
        targets: ['8.8.8.8', '2001:4860:4860::8888'],
        timeout_ms: 100,
        max_retries: 0
      },
      {
        resolver_factory: CreateResolverFactory({ resolver_behaviors })
      }
    );

    assert.equal(response.resolver_results.length, 1);
    assert.equal(response.resolver_results[0].target_results.length, 2);

    for (const target_result of response.resolver_results[0].target_results) {
      assert.equal(target_result.record_results.length, 1);
      assert.equal(target_result.record_results[0].record_type, 'PTR');
      assert.equal(target_result.record_results[0].status, 'success');
      assert.deepEqual(target_result.record_results[0].answers, ['dns.google']);
    }
  }
);

test(
  'GetReverseDnsRecords rejects non-IP targets before any resolver call.',
  async function () {
    await assert.rejects(
      async function RunInvalidReverseLookup(): Promise<void> {
        await GetReverseDnsRecords({
          resolvers: ['8.8.8.8:53'],
          targets: ['example.com']
        });
      },
      /Reverse lookups require IPv4 or IPv6 addresses/
    );
  }
);

test(
  'GetDnsRecords retries timeouts and succeeds on a later attempt.',
  async function () {
    let query_attempt_count = 0;

    const resolver_behaviors: fake_resolver_behavior_by_endpoint_t = {
      '9.9.9.9:53': {
        resolve_behavior: {
          'retry.test|A': async function ResolveWithTimeoutThenSuccess(): Promise<
            unknown[]
          > {
            query_attempt_count += 1;

            if (query_attempt_count === 1) {
              await new Promise((resolve) => setTimeout(resolve, 20));
              return ['203.0.113.10'];
            }

            return ['203.0.113.10'];
          }
        }
      }
    };

    const response = await GetDnsRecords(
      {
        resolvers: ['9.9.9.9:53'],
        targets: ['retry.test'],
        record_types: ['A'],
        timeout_ms: 5,
        max_retries: 1,
        concurrency_limit: 1
      },
      {
        resolver_factory: CreateResolverFactory({ resolver_behaviors })
      }
    );

    const record_result =
      response.resolver_results[0].target_results[0].record_results[0];

    assert.equal(record_result.status, 'success');
    assert.deepEqual(record_result.answers, ['203.0.113.10']);
    assert.equal(query_attempt_count, 2);
  }
);
