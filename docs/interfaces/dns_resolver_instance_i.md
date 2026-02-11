[**@opsimathically/dnsinfo**](../README.md)

***

[@opsimathically/dnsinfo](../README.md) / dns\_resolver\_instance\_i

# Interface: dns\_resolver\_instance\_i

Defined in: [types/project\_types.d.ts:74](https://github.com/opsimathically/dnsinfo/blob/57c91ecde7513242fe5a4f0bd4d7987c5365c991/src/types/project_types.d.ts#L74)

## Methods

### resolve()

> **resolve**(`hostname`, `rrtype`): `Promise`\<`unknown`[]\>

Defined in: [types/project\_types.d.ts:76](https://github.com/opsimathically/dnsinfo/blob/57c91ecde7513242fe5a4f0bd4d7987c5365c991/src/types/project_types.d.ts#L76)

#### Parameters

##### hostname

`string`

##### rrtype

[`dns_record_type_t`](../type-aliases/dns_record_type_t.md)

#### Returns

`Promise`\<`unknown`[]\>

***

### reverse()

> **reverse**(`ip_address`): `Promise`\<`string`[]\>

Defined in: [types/project\_types.d.ts:77](https://github.com/opsimathically/dnsinfo/blob/57c91ecde7513242fe5a4f0bd4d7987c5365c991/src/types/project_types.d.ts#L77)

#### Parameters

##### ip\_address

`string`

#### Returns

`Promise`\<`string`[]\>

***

### setServers()

> **setServers**(`servers`): `void`

Defined in: [types/project\_types.d.ts:75](https://github.com/opsimathically/dnsinfo/blob/57c91ecde7513242fe5a4f0bd4d7987c5365c991/src/types/project_types.d.ts#L75)

#### Parameters

##### servers

`string`[]

#### Returns

`void`
