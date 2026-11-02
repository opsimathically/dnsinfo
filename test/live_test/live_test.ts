import {
  GetDnsRecords,
  GetReverseDnsRecords,
  type dns_record_query_result_t,
  type dns_record_type_t,
  type dns_resolver_instance_i
} from '../../src/index';

(async function () {
  const dns_results = await GetDnsRecords({
    resolvers: [
      {
        resolver_id: 'google_ipv4',
        resolver_host: '8.8.8.8',
        resolver_port: 53
      },
      '[2001:4860:4860::8888]:53'
    ],
    targets: ['reddit.com', '1.1.1.1', '2606:4700:4700::1111'],
    record_types: ['A', 'AAAA', 'MX', 'TXT', 'PTR'],
    timeout_ms: 3000,
    max_retries: 1,
    concurrency_limit: 25
  });

  debugger;
})();
