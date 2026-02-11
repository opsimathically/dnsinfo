// Please See: https://www.npmjs.com/package/ts-to-zod

export type dns_record_type_input_t =
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

export type dns_resolver_object_input_t = {
  /**
   * @minLength 1
   * @maxLength 100
   */
  resolver_id?: string;
  /**
   * @minLength 1
   * @maxLength 255
   */
  resolver_host: string;
  /**
   * @minimum 1
   * @maximum 65535
   */
  resolver_port: number;
};

export type dns_resolver_endpoint_string_input_t = string;

export type dns_resolver_endpoint_input_t =
  | dns_resolver_object_input_t
  | dns_resolver_endpoint_string_input_t;

export type dns_lookup_request_input_t = {
  resolvers: dns_resolver_endpoint_input_t[];
  targets: string[];
  record_types?: dns_record_type_input_t[];
  /**
   * @minimum 1
   * @maximum 60000
   */
  timeout_ms?: number;
  /**
   * @minimum 0
   * @maximum 10
   */
  max_retries?: number;
  /**
   * @minimum 1
   * @maximum 1000
   */
  concurrency_limit?: number;
};

export type reverse_dns_lookup_request_input_t = {
  resolvers: dns_resolver_endpoint_input_t[];
  targets: string[];
  /**
   * @minimum 1
   * @maximum 60000
   */
  timeout_ms?: number;
  /**
   * @minimum 0
   * @maximum 10
   */
  max_retries?: number;
  /**
   * @minimum 1
   * @maximum 1000
   */
  concurrency_limit?: number;
};
