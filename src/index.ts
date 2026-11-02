import { Resolver } from 'node:dns/promises';
import { isIP } from 'node:net';

import {
  dns_lookup_request_input_t_zods,
  reverse_dns_lookup_request_input_t_zods
} from './zod_type_validators/custom_ts_to_zod_generated_validators';

import type {
  dns_lookup_request_input_t,
  reverse_dns_lookup_request_input_t
} from './types/custom_zod_types/custom_zod_types';

import type {
  dns_lookup_request_t,
  dns_lookup_response_t,
  dns_record_query_result_t,
  dns_record_type_t,
  dns_resolver_endpoint_t,
  dns_resolver_instance_i,
  dns_resolver_result_t,
  dns_runtime_options_t,
  dns_target_kind_t,
  dns_target_result_t,
  reverse_dns_lookup_request_t,
  reverse_dns_lookup_response_t
} from './types/project_types';

const default_timeout_ms = 3000;
const default_max_retries = 1;
const default_concurrency_limit = 25;

const default_forward_record_types: dns_record_type_t[] = [
  'A',
  'AAAA',
  'CNAME',
  'MX',
  'NS',
  'TXT',
  'SRV',
  'SOA',
  'CAA',
  'PTR'
];

const dns_record_type_allowlist = new Set<dns_record_type_t>(
  default_forward_record_types
);

type normalized_dns_resolver_t = {
  resolver_id: string;
  resolver_host: string;
  resolver_port: number;
  resolver_endpoint: string;
};

type normalized_lookup_request_t = {
  resolvers: normalized_dns_resolver_t[];
  targets: string[];
  target_kinds: dns_target_kind_t[];
  record_types: dns_record_type_t[];
  timeout_ms: number;
  max_retries: number;
  concurrency_limit: number;
};

function IsValidHostname(params: { hostname: string }): boolean {
  let normalized_hostname = params.hostname.trim();

  if (normalized_hostname.length === 0) {
    return false;
  }

  if (normalized_hostname.endsWith('.')) {
    normalized_hostname = normalized_hostname.slice(0, -1);
  }

  if (normalized_hostname.length === 0 || normalized_hostname.length > 253) {
    return false;
  }

  if (normalized_hostname.includes('..')) {
    return false;
  }

  const label_regex = /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$/;
  const hostname_labels = normalized_hostname.split('.');

  for (const label of hostname_labels) {
    if (!label_regex.test(label)) {
      return false;
    }
  }

  return true;
}

function DetermineTargetKind(params: { target: string }): dns_target_kind_t | null {
  const ip_version = isIP(params.target);

  if (ip_version === 4) {
    return 'ipv4';
  }

  if (ip_version === 6) {
    return 'ipv6';
  }

  if (IsValidHostname({ hostname: params.target })) {
    return 'hostname';
  }

  return null;
}

function FormatResolverEndpoint(params: {
  resolver_host: string;
  resolver_port: number;
}): string {
  if (isIP(params.resolver_host) === 6) {
    return `[${params.resolver_host}]:${params.resolver_port}`;
  }

  return `${params.resolver_host}:${params.resolver_port}`;
}

function IsValidResolverHost(params: { resolver_host: string }): boolean {
  const ip_version = isIP(params.resolver_host);

  if (ip_version === 4 || ip_version === 6) {
    return true;
  }

  return IsValidHostname({ hostname: params.resolver_host });
}

function ParsePort(params: {
  port_text: string;
  resolver_endpoint: string;
}): number {
  const parsed_port = Number(params.port_text);

  if (
    !Number.isInteger(parsed_port) ||
    parsed_port < 1 ||
    parsed_port > 65535
  ) {
    throw new Error(
      `Invalid resolver port in "${params.resolver_endpoint}". Port must be 1..65535.`
    );
  }

  return parsed_port;
}

function ParseResolverEndpointString(params: {
  resolver_endpoint: string;
  resolver_index: number;
}): normalized_dns_resolver_t {
  const resolver_endpoint = params.resolver_endpoint.trim();

  if (resolver_endpoint.length === 0) {
    throw new Error(
      `Resolver endpoint at index ${params.resolver_index} cannot be empty.`
    );
  }

  let resolver_host = '';
  let resolver_port = 0;

  if (resolver_endpoint.startsWith('[')) {
    const ipv6_match = resolver_endpoint.match(/^\[([^\]]+)\]:(\d{1,5})$/);

    if (!ipv6_match) {
      throw new Error(
        `Invalid IPv6 resolver endpoint "${resolver_endpoint}". Expected "[ipv6]:port".`
      );
    }

    resolver_host = ipv6_match[1];
    resolver_port = ParsePort({
      port_text: ipv6_match[2],
      resolver_endpoint
    });
  } else {
    const colon_count = (resolver_endpoint.match(/:/g) ?? []).length;

    if (colon_count > 1) {
      throw new Error(
        `Invalid resolver endpoint "${resolver_endpoint}". IPv6 endpoints must use "[ipv6]:port".`
      );
    }

    const split_index = resolver_endpoint.lastIndexOf(':');

    if (
      split_index <= 0 ||
      split_index === resolver_endpoint.length - 1
    ) {
      throw new Error(
        `Invalid resolver endpoint "${resolver_endpoint}". Expected "host:port".`
      );
    }

    resolver_host = resolver_endpoint.slice(0, split_index).trim();
    resolver_port = ParsePort({
      port_text: resolver_endpoint.slice(split_index + 1),
      resolver_endpoint
    });
  }

  if (!IsValidResolverHost({ resolver_host })) {
    throw new Error(
      `Invalid resolver host "${resolver_host}" in "${resolver_endpoint}".`
    );
  }

  return {
    resolver_id: `resolver_${params.resolver_index + 1}`,
    resolver_host,
    resolver_port,
    resolver_endpoint: FormatResolverEndpoint({ resolver_host, resolver_port })
  };
}

function NormalizeResolverEndpoint(params: {
  resolver_endpoint: dns_resolver_endpoint_t;
  resolver_index: number;
}): normalized_dns_resolver_t {
  if (typeof params.resolver_endpoint === 'string') {
    return ParseResolverEndpointString({
      resolver_endpoint: params.resolver_endpoint,
      resolver_index: params.resolver_index
    });
  }

  const resolver_host = params.resolver_endpoint.resolver_host.trim();
  const resolver_port = params.resolver_endpoint.resolver_port;
  const resolver_id = params.resolver_endpoint.resolver_id?.trim();

  if (!IsValidResolverHost({ resolver_host })) {
    throw new Error(
      `Invalid resolver host "${params.resolver_endpoint.resolver_host}".`
    );
  }

  if (
    !Number.isInteger(resolver_port) ||
    resolver_port < 1 ||
    resolver_port > 65535
  ) {
    throw new Error(
      `Invalid resolver port "${resolver_port}". Port must be 1..65535.`
    );
  }

  return {
    resolver_id:
      resolver_id && resolver_id.length > 0
        ? resolver_id
        : `resolver_${params.resolver_index + 1}`,
    resolver_host,
    resolver_port,
    resolver_endpoint: FormatResolverEndpoint({ resolver_host, resolver_port })
  };
}

function NormalizeResolvers(params: {
  resolvers: dns_lookup_request_input_t['resolvers'];
}): normalized_dns_resolver_t[] {
  if (params.resolvers.length === 0) {
    throw new Error('At least one resolver must be provided.');
  }

  return params.resolvers.map((resolver_endpoint, resolver_index) =>
    NormalizeResolverEndpoint({
      resolver_endpoint,
      resolver_index
    })
  );
}

function NormalizeForwardTargets(params: {
  targets: string[];
}): { targets: string[]; target_kinds: dns_target_kind_t[] } {
  if (params.targets.length === 0) {
    throw new Error('At least one target must be provided.');
  }

  const targets: string[] = [];
  const target_kinds: dns_target_kind_t[] = [];

  for (const target of params.targets) {
    const normalized_target = target.trim();

    if (normalized_target.length === 0) {
      throw new Error('Targets cannot contain empty strings.');
    }

    const target_kind = DetermineTargetKind({ target: normalized_target });

    if (!target_kind) {
      throw new Error(`Invalid target "${target}".`);
    }

    targets.push(normalized_target);
    target_kinds.push(target_kind);
  }

  return { targets, target_kinds };
}

function NormalizeReverseTargets(params: {
  targets: string[];
}): { targets: string[]; target_kinds: dns_target_kind_t[] } {
  if (params.targets.length === 0) {
    throw new Error('At least one reverse target must be provided.');
  }

  const targets: string[] = [];
  const target_kinds: dns_target_kind_t[] = [];

  for (const target of params.targets) {
    const normalized_target = target.trim();
    const ip_version = isIP(normalized_target);

    if (ip_version === 4) {
      targets.push(normalized_target);
      target_kinds.push('ipv4');
      continue;
    }

    if (ip_version === 6) {
      targets.push(normalized_target);
      target_kinds.push('ipv6');
      continue;
    }

    throw new Error(
      `Invalid reverse target "${target}". Reverse lookups require IPv4 or IPv6 addresses.`
    );
  }

  return { targets, target_kinds };
}

function NormalizeRecordTypes(params: {
  record_types: dns_lookup_request_input_t['record_types'];
}): dns_record_type_t[] {
  if (!params.record_types || params.record_types.length === 0) {
    return [...default_forward_record_types];
  }

  const record_type_set = new Set<dns_record_type_t>();

  for (const record_type of params.record_types) {
    if (!dns_record_type_allowlist.has(record_type)) {
      throw new Error(`Unsupported record type "${record_type}".`);
    }

    record_type_set.add(record_type);
  }

  return [...record_type_set];
}

function NormalizeConfig(params: {
  timeout_ms?: number;
  max_retries?: number;
  concurrency_limit?: number;
}): {
  timeout_ms: number;
  max_retries: number;
  concurrency_limit: number;
} {
  return {
    timeout_ms: params.timeout_ms ?? default_timeout_ms,
    max_retries: params.max_retries ?? default_max_retries,
    concurrency_limit: params.concurrency_limit ?? default_concurrency_limit
  };
}

function NormalizeDnsLookupRequest(params: {
  request: dns_lookup_request_input_t;
}): normalized_lookup_request_t {
  const resolvers = NormalizeResolvers({
    resolvers: params.request.resolvers
  });

  const target_data = NormalizeForwardTargets({
    targets: params.request.targets
  });

  const record_types = NormalizeRecordTypes({
    record_types: params.request.record_types
  });

  const config = NormalizeConfig({
    timeout_ms: params.request.timeout_ms,
    max_retries: params.request.max_retries,
    concurrency_limit: params.request.concurrency_limit
  });

  return {
    resolvers,
    targets: target_data.targets,
    target_kinds: target_data.target_kinds,
    record_types,
    timeout_ms: config.timeout_ms,
    max_retries: config.max_retries,
    concurrency_limit: config.concurrency_limit
  };
}

function NormalizeReverseDnsLookupRequest(params: {
  request: reverse_dns_lookup_request_input_t;
}): normalized_lookup_request_t {
  const resolvers = NormalizeResolvers({
    resolvers: params.request.resolvers
  });

  const target_data = NormalizeReverseTargets({
    targets: params.request.targets
  });

  const config = NormalizeConfig({
    timeout_ms: params.request.timeout_ms,
    max_retries: params.request.max_retries,
    concurrency_limit: params.request.concurrency_limit
  });

  return {
    resolvers,
    targets: target_data.targets,
    target_kinds: target_data.target_kinds,
    record_types: ['PTR'],
    timeout_ms: config.timeout_ms,
    max_retries: config.max_retries,
    concurrency_limit: config.concurrency_limit
  };
}

function GetResolverFactory(params: {
  runtime_options?: dns_runtime_options_t;
}): () => dns_resolver_instance_i {
  if (params.runtime_options?.resolver_factory) {
    return params.runtime_options.resolver_factory;
  }

  return function GetDefaultResolverFactory(): dns_resolver_instance_i {
    return new Resolver();
  };
}

function CreateTimeoutError(params: { timeout_ms: number }): NodeJS.ErrnoException {
  const timeout_error = new Error(
    `Query timed out after ${params.timeout_ms}ms.`
  ) as NodeJS.ErrnoException;
  timeout_error.code = 'ETIMEOUT';
  return timeout_error;
}

async function ExecuteWithTimeout<return_type_t>(params: {
  operation: () => Promise<return_type_t>;
  timeout_ms: number;
}): Promise<return_type_t> {
  let timeout_handle: NodeJS.Timeout | undefined;

  const timeout_promise = new Promise<never>((_resolve, reject) => {
    timeout_handle = setTimeout(() => {
      reject(CreateTimeoutError({ timeout_ms: params.timeout_ms }));
    }, params.timeout_ms);
  });

  try {
    return (await Promise.race([
      params.operation(),
      timeout_promise
    ])) as return_type_t;
  } finally {
    if (timeout_handle) {
      clearTimeout(timeout_handle);
    }
  }
}

function StringifyAnswerValue(params: { answer_value: unknown }): string {
  if (typeof params.answer_value === 'string') {
    return params.answer_value;
  }

  if (
    typeof params.answer_value === 'number' ||
    typeof params.answer_value === 'boolean'
  ) {
    return String(params.answer_value);
  }

  if (Array.isArray(params.answer_value)) {
    if (params.answer_value.every((element) => typeof element === 'string')) {
      return params.answer_value.join('');
    }

    return JSON.stringify(params.answer_value);
  }

  if (params.answer_value && typeof params.answer_value === 'object') {
    return JSON.stringify(params.answer_value);
  }

  return String(params.answer_value);
}

function NormalizeDnsAnswerValues(params: {
  answer_values: unknown[];
}): string[] {
  const normalized_answers = params.answer_values
    .map((answer_value) => StringifyAnswerValue({ answer_value }).trim())
    .filter((answer_value) => answer_value.length > 0);

  return [...new Set(normalized_answers)];
}

function ExtractErrorCodeAndMessage(params: {
  query_error: unknown;
}): { error_code: string; error_message: string } {
  if (params.query_error instanceof Error) {
    const query_error_as_errno = params.query_error as NodeJS.ErrnoException;
    return {
      error_code: query_error_as_errno.code ?? 'UNKNOWN_ERROR',
      error_message: params.query_error.message
    };
  }

  if (typeof params.query_error === 'string') {
    return {
      error_code: 'UNKNOWN_ERROR',
      error_message: params.query_error
    };
  }

  return {
    error_code: 'UNKNOWN_ERROR',
    error_message: 'Unknown DNS query error.'
  };
}

async function ExecuteDnsQueryWithRetries(params: {
  resolver_instance: dns_resolver_instance_i;
  target: string;
  target_kind: dns_target_kind_t;
  record_type: dns_record_type_t;
  timeout_ms: number;
  max_retries: number;
}): Promise<dns_record_query_result_t> {
  const query_started_at_ms = Date.now();
  let last_query_error: unknown = null;

  for (
    let attempt_index = 0;
    attempt_index <= params.max_retries;
    attempt_index += 1
  ) {
    try {
      const answer_values = await ExecuteWithTimeout({
        timeout_ms: params.timeout_ms,
        operation: async function RunQueryOperation(): Promise<unknown[]> {
          if (
            params.record_type === 'PTR' &&
            (params.target_kind === 'ipv4' || params.target_kind === 'ipv6')
          ) {
            return params.resolver_instance.reverse(params.target);
          }

          return params.resolver_instance.resolve(
            params.target,
            params.record_type
          );
        }
      });

      const normalized_answers = NormalizeDnsAnswerValues({
        answer_values
      });

      return {
        record_type: params.record_type,
        status: normalized_answers.length > 0 ? 'success' : 'empty',
        answers: normalized_answers,
        latency_ms: Date.now() - query_started_at_ms,
        queried_at: new Date().toISOString()
      };
    } catch (query_error) {
      last_query_error = query_error;
    }
  }

  const error_data = ExtractErrorCodeAndMessage({
    query_error: last_query_error
  });

  return {
    record_type: params.record_type,
    status: 'error',
    answers: [],
    latency_ms: Date.now() - query_started_at_ms,
    queried_at: new Date().toISOString(),
    error_code: error_data.error_code,
    error_message: error_data.error_message
  };
}

async function RunWithConcurrencyLimit(params: {
  task_functions: Array<() => Promise<void>>;
  concurrency_limit: number;
}): Promise<void> {
  if (params.task_functions.length === 0) {
    return;
  }

  let next_task_index = 0;

  const worker_count = Math.max(
    1,
    Math.min(params.concurrency_limit, params.task_functions.length)
  );

  async function RunWorker(): Promise<void> {
    while (next_task_index < params.task_functions.length) {
      const task_index = next_task_index;
      next_task_index += 1;
      await params.task_functions[task_index]();
    }
  }

  const worker_promises = Array.from({ length: worker_count }, () =>
    RunWorker()
  );

  await Promise.all(worker_promises);
}

function BuildResolverResultsSkeleton(params: {
  normalized_request: normalized_lookup_request_t;
}): dns_resolver_result_t[] {
  return params.normalized_request.resolvers.map((resolver) => {
    const target_results: dns_target_result_t[] =
      params.normalized_request.targets.map((target, target_index) => ({
        target,
        target_kind: params.normalized_request.target_kinds[target_index],
        record_results: params.normalized_request.record_types.map(
          (record_type): dns_record_query_result_t => ({
            record_type,
            status: 'error',
            answers: [],
            latency_ms: 0,
            queried_at: '',
            error_code: 'UNEXECUTED',
            error_message: 'Query not yet executed.'
          })
        )
      }));

    return {
      resolver_id: resolver.resolver_id,
      resolver_host: resolver.resolver_host,
      resolver_port: resolver.resolver_port,
      resolver_endpoint: resolver.resolver_endpoint,
      target_results
    };
  });
}

async function ExecuteLookup(params: {
  normalized_request: normalized_lookup_request_t;
  runtime_options?: dns_runtime_options_t;
}): Promise<dns_lookup_response_t> {
  const request_started_at = new Date().toISOString();
  const resolver_factory = GetResolverFactory({
    runtime_options: params.runtime_options
  });

  const resolver_results = BuildResolverResultsSkeleton({
    normalized_request: params.normalized_request
  });

  const task_functions: Array<() => Promise<void>> = [];

  for (
    let resolver_index = 0;
    resolver_index < params.normalized_request.resolvers.length;
    resolver_index += 1
  ) {
    const normalized_resolver = params.normalized_request.resolvers[resolver_index];
    const resolver_instance = resolver_factory();

    resolver_instance.setServers([normalized_resolver.resolver_endpoint]);

    for (
      let target_index = 0;
      target_index < params.normalized_request.targets.length;
      target_index += 1
    ) {
      const target = params.normalized_request.targets[target_index];
      const target_kind = params.normalized_request.target_kinds[target_index];

      for (
        let record_index = 0;
        record_index < params.normalized_request.record_types.length;
        record_index += 1
      ) {
        const record_type = params.normalized_request.record_types[record_index];

        task_functions.push(async function RunDnsQueryTask(): Promise<void> {
          const query_result = await ExecuteDnsQueryWithRetries({
            resolver_instance,
            target,
            target_kind,
            record_type,
            timeout_ms: params.normalized_request.timeout_ms,
            max_retries: params.normalized_request.max_retries
          });

          resolver_results[resolver_index].target_results[target_index].record_results[
            record_index
          ] = query_result;
        });
      }
    }
  }

  await RunWithConcurrencyLimit({
    task_functions,
    concurrency_limit: params.normalized_request.concurrency_limit
  });

  return {
    request_started_at,
    request_finished_at: new Date().toISOString(),
    resolver_results
  };
}

export async function GetDnsRecords(
  params: dns_lookup_request_t,
  runtime_options?: dns_runtime_options_t
): Promise<dns_lookup_response_t> {
  const validated_request =
    dns_lookup_request_input_t_zods.parse(params) as dns_lookup_request_input_t;

  const normalized_request = NormalizeDnsLookupRequest({
    request: validated_request
  });

  return ExecuteLookup({
    normalized_request,
    runtime_options
  });
}

export async function GetDnsRecordsFromResolvers(
  params: dns_lookup_request_t,
  runtime_options?: dns_runtime_options_t
): Promise<dns_lookup_response_t> {
  return GetDnsRecords(params, runtime_options);
}

export async function GetReverseDnsRecords(
  params: reverse_dns_lookup_request_t,
  runtime_options?: dns_runtime_options_t
): Promise<reverse_dns_lookup_response_t> {
  const validated_request = reverse_dns_lookup_request_input_t_zods.parse(
    params
  ) as reverse_dns_lookup_request_input_t;

  const normalized_request = NormalizeReverseDnsLookupRequest({
    request: validated_request
  });

  return ExecuteLookup({
    normalized_request,
    runtime_options
  });
}

export type {
  dns_lookup_request_t,
  dns_lookup_response_t,
  dns_record_query_result_t,
  dns_record_type_t,
  dns_resolver_config_t,
  dns_resolver_endpoint_t,
  dns_resolver_instance_i,
  dns_resolver_result_t,
  dns_runtime_options_t,
  dns_target_kind_t,
  dns_target_result_t,
  reverse_dns_lookup_request_t,
  reverse_dns_lookup_response_t
} from './types/project_types';
