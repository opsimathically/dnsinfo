export type dns_record_type_t =
  | 'A'
  | 'AAAA'
  | 'CNAME'
  | 'MX'
  | 'NS'
  | 'TXT'
  | 'SRV'
  | 'SOA'
  | 'CAA'
  | 'PTR';

export type dns_query_status_t = 'success' | 'empty' | 'error';

export type dns_target_kind_t = 'hostname' | 'ipv4' | 'ipv6';

export type dns_resolver_config_t = {
  resolver_id?: string;
  resolver_host: string;
  resolver_port: number;
};

export type dns_resolver_endpoint_t = dns_resolver_config_t | string;

export type dns_lookup_request_t = {
  resolvers: dns_resolver_endpoint_t[];
  targets: string[];
  record_types?: dns_record_type_t[];
  timeout_ms?: number;
  max_retries?: number;
  concurrency_limit?: number;
};

export type reverse_dns_lookup_request_t = {
  resolvers: dns_resolver_endpoint_t[];
  targets: string[];
  timeout_ms?: number;
  max_retries?: number;
  concurrency_limit?: number;
};

export type dns_record_query_result_t = {
  record_type: dns_record_type_t;
  status: dns_query_status_t;
  answers: string[];
  latency_ms: number;
  queried_at: string;
  error_code?: string;
  error_message?: string;
};

export type dns_target_result_t = {
  target: string;
  target_kind: dns_target_kind_t;
  record_results: dns_record_query_result_t[];
};

export type dns_resolver_result_t = {
  resolver_id: string;
  resolver_host: string;
  resolver_port: number;
  resolver_endpoint: string;
  target_results: dns_target_result_t[];
};

export type dns_lookup_response_t = {
  request_started_at: string;
  request_finished_at: string;
  resolver_results: dns_resolver_result_t[];
};

export type reverse_dns_lookup_response_t = dns_lookup_response_t;

export interface dns_resolver_instance_i {
  setServers(servers: string[]): void;
  resolve(hostname: string, rrtype: dns_record_type_t): Promise<unknown[]>;
  reverse(ip_address: string): Promise<string[]>;
}

export type dns_runtime_options_t = {
  resolver_factory?: () => dns_resolver_instance_i;
};
