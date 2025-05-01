# Verifiable Credentials Decentralized Status

## Abstract

Credentials give information about a subject that helps in its recognition by a third party, usually to provide a service or state an assertion given its traits. The verification of credentials needs additional information to assert the validity of the information contained in it. This specification provides a way to store verifiable credential status and verify it in a decentralized context. The architecture enables the verifiable credential holders to store derived status information that can only be resolved by the issuer without prior centralized storage.

## Status of the document

This document is a working draft of a possible specification.

## Motivation

As stated the status adds information to verifiable credentials to assert credential validity. That piece of information annotates data, the closer it is to the actual information it denotes, the less there are possibilities of uncoupling of the data and its status. Providing a way to store both information at the same place gives a way to provide that proximity. The decentralized way of seeing status storage differ from actual status list specifications since it requires no centralized storage for statuses which makes them faster to resolve and then better scales with the projected number of emitted verifiable credentials. It also makes other tradeoffs about privacy (see 6. Privacy considerations) staying reasonable with those concerns. This specification is open to contributions to better solve the status issue deepening further the work on revocation which is still ongoing.

## 1. Introduction

### 1. Specifications

- HOTP

## 2. Data Model

### 2.1 Status Tokens

Status tokens are the major components of this specification. They enable holders to store the status information without disclosing it, making the status only resolvable by the issuer. Those tokens are made of two parts: the first contains encoded information that helps resolve the second part. The latter contains a status cryptographic derivation.

![token anatomy](https://raw.githubusercontent.com/malach-it/vc-decentralized-status/main/images/sotp.png)

#### 2.2 Example

```
BiwBG3EYQhLDjAMA~2f0f96b9
```

### 2.2 Status information

The status information, as the first part of status tokens, is encoded to store a low-weighted payload that contains the iat and the status token time to live. It helps to resolve the status contained in the derived token. Not being part of token verification algorithm, this part contains information about when the token was issued. The contained information is stored in a binary format and URL-safe base 64 encoded.

```
<iat>{4}<binary encode Time To Live>{4}
```

The iat may be 7 bytes long and binary encoded. The time to live may also be padded binary encoded integer to save storage. Those parts may be concatenated to form the status information.

### 2.1 Derived Status

![Status derivation](https://raw.githubusercontent.com/malach-it/vc-decentralized-status/main/images/non-opaque-salt.png)

Using the HOTP algorithm with a secret kept by the issuer and a counter made of Unix timestamp and status shift, we can derive the status but keep also the expiry information in the same token. Noticing that the shift preserves the validity range size, the next checks within the expiration time will succeed by providing the same shift. Also, the more you take HOTP HMAC value bytes, the more the token will fail to collide improving the entropy of the derivation.

## 4. Implementation

### 4.1 Crafting a verifiable credential status token

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

### 4.2 Resolving a verifiable credential status token

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

resolve_status_token(secret: string, status_token: string): string {
	[token_info, derived_status] = SPLIT(status_token, '~')
	info = decode_token_info(BASE64_DECODE(token_info))

  statuses = CLONE(@status_table)
  result = 'invalid'
  while status = POP(statuses):
    if HOTP(secret, DIV(NOW(:second), info[ttl]) + shift(status)) == derived_status
			return status
}
```

### 4.3 Example implementation

You can find an example implementation [here](https://hexdocs.pm/boruta_ssi/0.1.0-beta.1/Boruta.VerifiableCredentials.Status.html).

## 5. Privacy Considerations

### 5.1 Decentralized Architecture

Status tokens are self-contained but only resolvable by the issuer which owns a secret component, the decentralized architecture gives a way to have low-weighted storage points. To state the validity of verifiable credentials and keep the holder's privacy, verifiers can resolve the status of the presented credentials without disclosing the data contained in it to the issuer in any manner. Mitigated by the fact that Time To Live information can give hints about the type of credential resolved.

### 5.2 Status table

The status table represents the list of possible statuses that are encoded into a shift integer for lowering to a tiny list the issuer needed storage. The status list may be standardized globally or issuer-wide for the issuer emitted set of credentials to lower the verifiable credentials type disclosability. The status token being part of a credential and including a time to live, a way to check if statuses are hidden is to resolve it against a given status table whether the status token is valid to ensure a status is found. Otherwise, a hidden status has been set by the issuer. This check can be performed with a past timestamp, then, once issued there will always be a way to check if the status of a token has been hidden provided an issuer secret. Statuses may help categorize the annotated data. In order to do so, the element of the status table may be part of the same category.

### 5.3 Granularity

Some verifiable credential formats support selective disclosure enabling to share part of the data contained in the verifiable credential payload without disclosing the remaining part. Status tokens can reference individual information or a set of disclosures. Taking the example of [Selective Disclosure for JWTs](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-09.html), the status token can replace the suggested opaque salt to include the status information of the associated disclosure. The decentralization architecture of this suggested specification makes the status storage to be handled by the holders helping to reduce the weight of single-place storage.

### 5.4 Annotation

By definition a status is an annotation on the data it denotes. Following this specification, the issuer is not limited for the statuses it set which may include statuses the holder may not be aware of. While this information is not disclosable, the issuer can hide statuses from the holder and the verifier which gives the ability to track them on verfication. When the verifier contacts the issuer to get the status, the latter has the ability to track the remote ip of the verifier making then the usage of the custom statuses trackable. This issue may be mitigated by reducing the possible statuses which may not be possible with the suggested algorithms or by making the status publicly readable for both the holder and the verifier.

### 5.5 Issuer trust

Status tokens are emitted by the issuer of the backed-up data. This issuer is the trust anchor of both the data and the status being the single source of truth of those information. The verifier is to trust the issuer providing a factor of trust for the holder delivered information. Here the suggested framework gives the ability to have that trust chain by directly resolving the status requesting the issuer which creates a direct link between both parties. That enforces trust through the DID document and the SSL abilities of the issuer domain, being again a single source of truth for trust of the data and the status giving all the required insurance to provide a service for the verifier. The link between the issuer and the verifier for trust is not herein anonymous, failing the privacy of the issuer but keeping the holder one which is the most important factor of decentralized identity beyond trust.

## 6. About revocation

Considering the status as an annotation and that annotations prove the data and the data proves the annotations, seeing them as paradoxes, it is not possible to see revocation within the proposed framework for statuses. It would enforce to break one of the before statements proving the annotation is false and not yet to be considered. Then the revocation subject is quite an important subject to fix impairments. Those contain the identity information itself as a component and corrective actions in the annotation would fail the privacy brought by the decentralized identity concepts enforcing both the holder and the verifier to disclose identity information to the issuer.

## 7. Going further, status chains

It would be possible to store a list of statuses composing the status tokens one with the other. Composing the status tokens would result to a merkle tree. This would permit for an issuer to emit more than a single status but a list. The hash of HOTP values are to be taken at a single point of time providing the same hash format for all the emitted tokens. The verification would be made by rebuilding the composed tree, one status after the other keeping the same category building a merkle tree from result to result. The composition law for the given status tokens help to store more data staying in the same category.

![Status chains](https://raw.githubusercontent.com/malach-it/vc-decentralized-status/main/images/status-chains.png)

### 7.1 Choosing a status among the chain

Apart from a single status token, the corresponding status list can be derived using a composition law, the status being a choice among the given list. This would enforce the issuer to provide the status list state at token emission. The pattern would not enforce the issuer to include the list associated to the token, but the contracted list must contain the status given by the associated token to provide the validity of the couple list / choice. Further discussions can be made for having choices that do not influence the resulting status token which is at first sight not possible with modern computing.

![Couple list / choice](https://raw.githubusercontent.com/malach-it/vc-decentralized-status/main/images/chosing-a-status-among-a-list.png)

### 7.2 Public statuses

An other way to see status would be to include the status list in the chain and publicly expose those statuses and the status list derivation, that would help to prevent from the hidden statuses issue. Then status tokens would be publicly solvable, the token being private. An example would be to have the statuses given, namely "valid", "suspended", "revoked" and have the signing did as secret.

### 7.3 Choosing multiple statuses

Using a binary sum as composition law, multiple statuses can be choosen from the given list. Giving them in their textual form along with the remaining sum of the other status tokens help to prove the statuses are part of the associated status list. This would also fix the hidden statuses issue. Computing the chosen status tokens sum and adding it to the rest results to the status list token. This would be a way to enable selective disclosure. It helps to selectively disclose status information without disclosing the number of statuses included in the token. Metaphoring the statuses as the verbal communication and the remaining sum as the non-verbal one.

![Status sum](https://raw.githubusercontent.com/malach-it/vc-decentralized-status/main/images/choosing-multiple-statuses.png)

If the status list forms a coherent set, some disclosed subsets of that list can give meaningful information by themselves, choosing such a set would express information about the annotated data itself. That ability of such choice should be inherent to the coherence of the list and is not covered by this draft. It is probable that in modern computing only human can perform this.
