# Verifiable Credentials Decentralized Status

## Abstract

Credentials give information about a subject that helps in its recognition by a third party, usually to provide a service or state an assertion giving its traits. The verification of credentials needs additional information to assert the validity of the information contained in it. This specification provides a way to store verifiable credential status information and verify it in a decentralized context. The architecture enables for the verifiable credentials holders to store derived status information that can only be resolved by the issuer without prior storage.

## Status of the document

This document is a working draft of a possible specification.

## 1. Introduction
### 1.1 Underlying specifications
- HOTP
### 1.2 Underlying Concepts
- Verifying a verifiable credential

### 1.3 Conformance
TBD

### 2. Terminology

On top of the [Verifiable Credentials Data Model v2.0 Terminology](https://www.w3.org/TR/vc-data-model-2.0/#terminology) the following terms will be used:

- __verifiable credential status__: The status of a verifiable credential at a given point of time. The different statuses give information about the validity of the verifiable credential data. This information can be given for a set of verifiable credentials providing the status of each individual information in a more convinient way.
- __status information__
- __status token__

## 3. Data Model
### 3.1 Status Tokens
### 3.2 Status information
### 3.1 Derived Status
## 4. Status Information Requests
### 4.1 Decentralized IDentifier services

To fetch the status of a verifiable credentials, the verifier is suggested to make use of [Decentralized IDentifiers parameters](https://www.w3.org/TR/did-core/#did-parameters). The registration of a service within the DID document help to proxy an issuer endpoint that has the ability resolve the status. The issuer may implement the 6.2 algorithm to resolve the status token value. The Verifiable credentials issuer may use the private key associated with the public one stored remotely in the associated DID document to sign a credential. The proximity of the signing key and the way to get the credential status help the verifier to add the lesser to its implementation but can consider status verification as an addition. The DID service registration is temper proof giving a way to keep status resolvance endpoints history. The resolvance endpoint must be secured with TLS and provide a valid certificate to assess the issuer authority which may be part of a trust chain. The registered service may proxy the resolvance of the status token. That service endpoint would use the `relativeRef` component to get the status token parameter and respond with the status for proxied verifier requests.

#### Example
A. Did document
```
[...]
  "service": [
    {
      "id": "#statusSolver",
      "serviceEndpoint": "https://oauth.boruta.patatoid.fr/did/public/resolve_status/",
      "type": "LinkedDomains"
    }
  ]
[...]
```
B. Request
```
GET https://api.godiddy.com/0.1.0/universal-resolver/identifiers/did:indy:danube:VUQ36xG7PRccjojjgzmJBa?service=statusSolver&relativeRef=YjY4NTAzMTgBw6EzwoAhLDc=~1e5e40e7


303 See Other
Location: https://oauth.boruta.patatoid.fr/did/public/resolve_status/YjY4NTAzMTgBw6EzwoAhLDc=~1e5e40e7
```
### 4.2 Interfaces
## 5. Algorithms
### 5.1 Status information
```
<random bytes>{4}<binary encode Time To Live>{4}<binary encoded status>{1}+
```
### 5.2 Status Derivated token
## 6. Usage
### 6.1 Crafting a verifiable credential status token
```
@status_table = { status: string -> shift: int }
shift(status: string): int {
  @status_table[status]
}
generate_status_token(secret: string, ttl: int, status: string): int {
  random = RANDOM_BYTES(4)
  time_to_live = BINARY_ENCODE(ttl)
  statuses = MAP(@status_table, lambda s: BINARY_ENCODE(shift(s)))

  token_info = BASE64_ENCODE(random + time_to_live + statuses)
  derived_status = HTOP(secret, DIV(NOW(), ttl) + shift(status))

  return "<token_info>~<derived_status>"
}
```
### 6.2 Resolving a verifiable credential status token
```
@status_table = { status: string -> shift: int }
decode_token_info(token_info: string): hashtable {
	result = REDUCE(
		BYTES(status_token),
		{ ttl => [], statuses => [], memory => [] },
		lambda (byte, index), acc:
			CASE index
			WHEN index < 4
				acc
			WHEN index < 7
				PUSH(acc[memory], byte)
				return acc
			WHEN index == 7
				PUSH(acc[memory], byte)
				acc[ttl] = BINARY_DECODE(acc[memory])
				RESET(acc[memory])
				return acc
			WHEN index > 7
				PUSH(acc[statuses], byte)
				return acc
	)
	DELETE result[memory]
	return result
}

resolve status_token(secret: string, status_token: string): string {
	[token_info, derived_status] = SPLIT(status_token, '~')
	info = decode_token_info(BASE64_DECODE(token_info))
	REDUCE(
		@status_table,
		'invalid',
		lambda (status, shift), result:
			if HOTP(secret, DIV(NOW(), info[ttl]) + shift) == derived_status
				return status
			else
				return 'invalid'
	)
}
```

## 7. Privacy Considerations

### 7.1 Decentralized Architecture

Status tokens are self-contained but only resolvable by the issuer which own a secret component, the decentralized architecture give a way to have low weighted storage points. To state the status of verifiable credentials and keep the holder privacy, verifiers can resolve the status of the presented verifiable credentials without disclosing the resolved credential to the issuer in any manner. Mitigated by the fact that Time To Live information can give hints about the type of credential resolved. The status information contained in the token information can be a disclosure of the type of credential if not standarized.

### 7.2 Status list

The status list represents the association of statuses with an integer shift for lowering to a tiny list the issuer needed storage. Ths integer shifts list is encoded in the status token so can be considered as public. The status list may be standarized globally or issuer wide for the whole set of credentials emmited by an issuer to lower the verifiable credentials type disclosability.

### 7.3 Granularity

Some verifiable credential formats support selective disclosure enabling to share part of the data contained in the verifiable credential payload without disclosing the remaining part. Status tokens can reference individual information or a set of disclosures. Taking the example of [Selective Disclosure for JWTs](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-09.html), the status token can replace the suggested opaque salt to include the status information of the associated disclosure. The decentralization architecture of this suggested specification makes the status storage to be handled by the holders helping to reduce to weight of single place storages.
