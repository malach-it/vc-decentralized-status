# Verifiable Credentials Decentralized Status

## Abstract

Credentials give information about a subject that helps in its recognition by a third party, usually to provide a service or state an assertion given its traits. The verification of credentials needs additional information to assert the validity of the information contained in it. This specification provides a way to store verifiable credential status and verify it in a decentralized context. The architecture enables the verifiable credentials holders to store derived status information that can only be resolved by the issuer without prior centralized storage.

## Status of the document

This document is a working draft of a possible specification.

## Motivation

As stated the status adds information to verifiable credentials to assert credential validity. That piece of information anotates data, the closer it is to the actual information it denotes, the less there are possibilities of uncoupling of the data and its status. Providing a way to store both information at the same place gives a way to have that proximity. The decentralized way of seeing status storage differ from actual status list specifications since it requires no centralized storage for statuses which makes them faster to resolve and then better scales with the projected number of emitted verifiable credentials. It also makes other tradeoffs about privacy (see 6. Privacy considerations) staying reasonable with those concerns. This specification is open to contributions to better solve the status issue deepening further the work on revocation which is still ongoing.

## 1. Introduction
### 1.1 Underlying specifications

- HOTP
- Decentralized IDentifiers
- Verifiable Credentials Data Model

### 1.2 Underlying Concepts

- Verifying a verifiable credential

### 1.3 Conformance

TBD

### 2. Terminology

On top of the [Verifiable Credentials Data Model v2.0 Terminology](https://www.w3.org/TR/vc-data-model-2.0/#terminology) the following terms will be used:

- __verifiable credential status__: The status of a verifiable credential at a given point in time. The different statuses give information about the validity of the verifiable credential data. This information can be given for a set of verifiable credentials providing the status of each piece of information in a more convenient way.
- __status information__
- __status token__
- __status table__

## 3. Data Model
### 3.1 Status Tokens

Status tokens are the major components of this specification. They enable holders to store the status information without disclosing it, making the status only resolvable by the issuer. Those tokens are made of two parts: the first contains encoded information that helps resolve the second part. The latter contains a status cryptographic derivation.

![token anatomy](https://raw.githubusercontent.com/malach-it/vc-decentralized-status/main/images/sotp.png)

#### Example
```
wpfDjsKrwrkSw4wDAA~3a479fde
```

### 3.2 Status information

The status information, as the first part of status tokens, is encoded to store a low-weighted payload that contains the iat and the token time to live. It helps to resolve the status contained in the derived token. Not being part of token verification algorithm, this part contains information about when the token was issued. The contained information is stored in a binary format and URL-safe base 64 encoded.

```
<iat>{4}<binary encode Time To Live>{4}
```

The iat may be a 7 bytes long and binary encoded. The time to live may also be padded binary encoded integer to save storage. Those parts may be concatenated to form the status information.

### 3.1 Derived Status
![Status derivation](https://raw.githubusercontent.com/malach-it/vc-decentralized-status/main/images/non-opaque-salt.png)

Using the HOTP algorithm with a secret kept by the issuer and a counter made of Unix timestamp and status shift, we can derive the status but keep also the expiry information in the same token. Noticing that the shift preserves the validity range size, the next checks within the expiration time will succeed by providing the same shift. Also, the more you take HOTP HMAC value bytes, the more the token will fail to collide improving the entropy of the derivation.

## 4. Status Information Requests
### 4.1 Decentralized IDentifier services

To fetch the status of verifiable credentials, the verifier is suggested to make use of [Decentralized IDentifiers parameters](https://www.w3.org/TR/did-core/#did-parameters). The registration of a service within the DID document helps to proxy an issuer endpoint that has the ability to resolve the status. The issuer may implement the 6.2 algorithm to resolve the status token value. The Verifiable credentials issuer may use the private key associated with the public one stored remotely in the associated DID document to sign a credential. The proximity of the signing key and the way to get the credential status help the verifier to add the lesser to its implementation but can consider status verification as an addition. The DID service registration gives a way to keep status resolvance endpoints unforgeable history. The resolvance endpoint must be secured with TLS and provide a valid certificate to assess the issuer authority which may be part of a trust chain. The registered service may proxy the resolvance of the status token. That service endpoint would use the `relativeRef` component to get the status token parameter and respond with the status for proxied verifier requests.

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
GET https://api.godiddy.com/0.1.0/universal-resolver/identifiers/did:indy:danube:VUQ36xG7PRccjojjgzmJBa?service=statusSolver&relativeRef=wpfDjsKrwrkSw4wDAA~3a479fde


303 See Other
Location: https://oauth.boruta.patatoid.fr/did/public/resolve_status/wpfDjsKrwrkSw4wDAA~3a479fde
```

### 4.2 Interfaces

TBD

## 5. Implementation
### 5.1 Crafting a verifiable credential status token

```
@status_table = [ status: string ]
shift(status: string): int {
  BINARY_DECODE_UNSIGNED(status)
}
generate_status_token(secret: string, ttl: int, status: string): int {
  iat = BINARY_ENCODE(NOW(:microsecond)) # 7 bytes long
  time_to_live = PAD_LEFT(BINARY_ENCODE(ttl), 4) # 4 bytes long

  token_info = BASE64_ENCODE(iat + time_to_live)
  derived_status = HTOP(secret, DIV(NOW(:second), ttl) + shift(status))

  return "<token_info>~<derived_status>"
}
```

### 5.2 Resolving a verifiable credential status token

```
@status_table = [ status: string ]
shift(status: string): int {
  BINARY_DECODE_UNSIGNED(BINARY_ENCODE(status))
}
decode_token_info(token_info: string): hashtable {
  result = REDUCE(
      BYTES(token_info),
      { iat => 0, ttl => 0, memory => [] },
      lambda (byte, index), acc:
      CASE index
      WHEN index == 7
        PUSH(acc[memory], byte)
        acc[iat] = BINARY_DECODE(acc[memory])
        RESET(acc[memory])
        return acc
      WHEN index == 10
        PUSH(acc[memory], byte)
        acc[ttl] = BINARY_DECODE(acc[memory])
        RESET(acc[memory])
        return acc
      ELSE
        PUSH(acc[memory], byte)
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
		lambda status, result:
			if HOTP(secret, DIV(NOW(), info[ttl]) + shift(status)) == derived_status
				return status
			else
				return result
	)
}
```

## 6. Privacy Considerations

### 6.1 Decentralized Architecture

Status tokens are self-contained but only resolvable by the issuer which owns a secret component, the decentralized architecture gives a way to have low-weighted storage points. To state the validity of verifiable credentials and keep the holder's privacy, verifiers can resolve the status of the presented credentials without disclosing the data contained in it to the issuer in any manner. Mitigated by the fact that Time To Live information can give hints about the type of credential resolved.

### 6.2 Status table

The status table represents the list of possible statuses that are encoded into a shift integer for lowering to a tiny list the issuer needed storage. The status list may be standardized globally or issuer-wide for the issuer emitted set of credentials to lower the verifiable credentials type disclosability. The status token being part of a credential and including a time to live, a way to check if statuses are hidden is to resolve it against a given status table whether the status token is valid to ensure a status is found. Otherwise, a hidden status has been set by the issuer. This check can be performed with a past timestamp, then, once issued there will always be a way to check if the status of a token has been hidden provided an issuer secret. Statuses may help categorize the anotated data. In order to do so, the element of the status table may be part of the same category.

### 6.3 Granularity

Some verifiable credential formats support selective disclosure enabling to share part of the data contained in the verifiable credential payload without disclosing the remaining part. Status tokens can reference individual information or a set of disclosures. Taking the example of [Selective Disclosure for JWTs](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-09.html), the status token can replace the suggested opaque salt to include the status information of the associated disclosure. The decentralization architecture of this suggested specification makes the status storage to be handled by the holders helping to reduce the weight of single-place storage.

### 6.4 Anotation

By definition a status is an anotation on the data it denotes. Following this specification, the issuer is not limited for the statuses it set which may include statuses the holder may not be aware of. While this information is not disclosable, the issuer can hide statuses from the holder and the verifier which gives the ability to track them on verfication. When the verifier contacts the issuer to get the status, the latter has the ability to track the remote ip of the verifier making then the usage of the custom statuses trackable. This issue may be mitigated by reducing the possible statuses which may not be possible with the suggested algorithms or by making the status publicly readable for both the holder and the verifier.

## 7. About revocation

Considering the status as an annotation and that annotations prove the data and the data proves the annotations, seeing them as paradoxes, it is not possible to see revocation within the proposed framework for statuses. It would enforce to break one of the before statements proving the annotation is false and not yet to be considered. Then the revocation subject is quite an important subject to fix impairments. Those contain the identity information itself as a component and corrective actions in the annotation would fail the privacy brought by the decentralized identity concepts enforcing both the holder and the verifier to disclose identity information to the issuer.
