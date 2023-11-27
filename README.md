# Spec compliant SD-JWT type-rich implementation for TypeScript

[![GitHub release (latest by date)](https://img.shields.io/github/v/release/cheqd/.github?color=green&label=stable%20release&style=flat-square)](https://github.com/cheqd/.github/releases/latest) ![GitHub Release Date](https://img.shields.io/github/release-date/cheqd/.github?color=green&style=flat-square) [![GitHub license](https://img.shields.io/github/license/cheqd/.github?color=blue&style=flat-square)](https://github.com/cheqd/.github/blob/main/LICENSE)

[![GitHub release (latest by date including pre-releases)](https://img.shields.io/github/v/release/cheqd/.github?include_prereleases&label=dev%20release&style=flat-square)](https://github.com/cheqd/.github/releases/) ![GitHub commits since latest release (by date)](https://img.shields.io/github/commits-since/cheqd/.github/latest?style=flat-square) [![GitHub contributors](https://img.shields.io/github/contributors/cheqd/.github?label=contributors%20%E2%9D%A4%EF%B8%8F&style=flat-square)](https://github.com/cheqd/.github/graphs/contributors)

[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/cheqd/.github/dispatch.yml?label=workflows&style=flat-square)](https://github.com/cheqd/.github/actions/workflows/dispatch.yml) [![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/cheqd/.github/codeql.yml?label=CodeQL&style=flat-square)](https://github.com/cheqd/.github/actions/workflows/codeql.yml) ![GitHub repo size](https://img.shields.io/github/repo-size/cheqd/.github?style=flat-square)

## ℹ️ Overview

### Further information

Checkout the [documentation regarding SD-JWTs](https://docs.walt.id/v/ssikit/concepts/selective-disclosure), to find out more.

## What is SD-JWT?

This library implements the **Selective Disclosure JWT (SD-JWT)**
specification:  [draft-ietf-oauth-selective-disclosure-jwt-06](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/06/).

### Features

* **Create and sign** SD-JWT tokens
  * Choose selectively disclosable payload fields (SD fields)
  * Create digests for SD fields and insert into JWT body payload
  * Create and append encoded disclosure strings for SD fields to JWT token
  * Add random or fixed number of **decoy digests** on each nested object property
* **Present** SD-JWT tokens
  * Selection of fields to be disclosed
  * Support for appending optional holder binding
* Full support for **nested SD fields** and **recursive disclosures**
* **Parse** SD-JWT tokens and restore original payload with disclosed fields
* **Verify** SD-JWT token
  * Signature verification
  * Hash comparison and tamper check of the appended disclosures
* Support for **integration** with various crypto libraries and frameworks, to perform the cryptographic operations and key management
