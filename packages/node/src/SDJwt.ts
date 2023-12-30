import { fromString, toString } from 'uint8arrays';
import { AsyncJWTCryptoProvider } from './AsyncJWTCryptoProvider.js';
import { JWTCryptoProvider } from './JWTCryptoProvider.js';
import { SDMap } from './SDMap.js';
import { SDPayload } from './SDPayload.js';
import { SDisclosure } from './SDisclosure.js';
import { VerificationResult, defaultVerificationResult } from './VerificationResult.js';
import { JSONObject, JSONWebKey, UndisclosedPayload } from './utils/types.js';

export class SDJwt extends Object {
	static readonly DIGESTS_KEY = '_sd' as const;
	static readonly DIGESTS_ALG_KEY = '_sd_alg' as const;
	static readonly SEPARATOR = '~' as const;
	static readonly SD_JWT_PATTERN =
		'^(?<sdjwt>(?<header>[A-Za-z0-9-_]+).(?<body>[A-Za-z0-9-_]+).(?<signature>[A-Za-z0-9-_]+))(?<disclosures>(~([A-Za-z0-9-_]+))+)?(~(?<holderjwt>([A-Za-z0-9-_]+).([A-Za-z0-9-_]+).([A-Za-z0-9-_]+))?)?$' as const;

	/**
	 * Encoded disclosures, included in this SD-JWT.
	 */
	readonly disclosures: ReadonlySet<string>;

	readonly disclosureObjects: SDisclosure[];

	readonly undisclosedPayload: UndisclosedPayload;

	readonly fullPayload: JSONObject;

	readonly digestedDisclosures: ReadonlyMap<string, SDisclosure>;

	readonly sdMap: SDMap;

	/**
	 * The algorithm used to sign this SD-JWT, e.g. 'ES256K-R', 'EdDSA, included in the header.
	 */
	readonly algorithm: string;

	/**
	 * The key id of the key used to sign this SD-JWT, included in the header.
	 */
	readonly keyId?: string;

	/**
	 * the signature key in JWK format, included in the header, if present.
	 */
	readonly jwk?: JSONWebKey;

	constructor(
		public readonly jwt: string,
		protected readonly header: JSONObject,
		protected readonly sdPayload: SDPayload,
		public readonly holderJwt?: string | null,
		protected readonly isPresentation: boolean = false
	) {
		super();
		this.disclosures = new Set(sdPayload.sDisclosures.map((sd) => sd.disclosure));
		this.disclosureObjects = sdPayload.sDisclosures;
		this.undisclosedPayload = sdPayload.undisclosedPayload;
		this.fullPayload = sdPayload.fullPayload;
		this.digestedDisclosures = sdPayload.digestedDisclosures;
		this.sdMap = sdPayload.sdMap;
		this.algorithm = header.alg
			? (header.alg as string)
			: (function () {
					throw new Error('Invalid SD-JWT');
			  })();
		this.keyId = header.kid ? (header.kid as string) : undefined;
		this.jwk = header.jwk ? (header.jwk as JSONWebKey) : undefined;
	}

	override toString() {
		return this.toFormattedString(this.isPresentation);
	}

	toFormattedString(formatForPresentation: boolean): string {
		return [this.jwt]
			.concat(this.disclosures.size > 0 ? [...this.disclosures] : [])
			.concat(this.holderJwt ? [this.holderJwt] : formatForPresentation ? [''] : [])
			.join(SDJwt.SEPARATOR);
	}

	/**
	 * Present SD-JWT with selection of disclosures.
	 * @param sdMap selective disclosure map, indicating whether to disclose each disclosure in the presentation, per field.
	 * @param withHolderJwt optional holder JWT as holder binding to include in the SD-JWT presentation.
	 */
	present(sdMap?: SDMap | null, withHolderJwt?: string | null): SDJwt {
		return new SDJwt(
			this.jwt,
			this.header,
			sdMap ? this.sdPayload.withSelectiveDisclosures(sdMap) : this.sdPayload.withoutSelectiveDisclosures(),
			withHolderJwt,
			true
		);
	}

	/**
	 * Present SD-JWT with either all disclosures or none.
	 */
	presentAll(discloseAll: boolean, withHolderJwt?: string | null): SDJwt {
		return new SDJwt(
			this.jwt,
			this.header,
			discloseAll ? this.sdPayload : this.sdPayload.withoutSelectiveDisclosures(),
			withHolderJwt || this.holderJwt,
			true
		);
	}

	/**
	 * Verify SD-JWT by checking the signature and matching the disclosures against the digests in the payload.
	 * @param jwtCryptoProvider synchronous JWT crypto provider to use for signature verification, that implements standard JWT signing and verification.
	 * @param options optional pass-through options.
	 */
	verify(jwtCryptoProvider: JWTCryptoProvider, options?: any): VerificationResult<SDJwt> {
		const jwtVerificationResult = jwtCryptoProvider.verify(this.jwt, options);
		return defaultVerificationResult(
			this,
			jwtVerificationResult.verified,
			jwtVerificationResult.verified && this.sdPayload.verifyDisclosures(),
			jwtVerificationResult.message
		);
	}

	/**
	 * Verify SD-JWT by checking the signature and matching the disclosures against the digests in the payload.
	 * @param jwtCryptoProvider asynchronous JWT crypto provider to use for signature verification, that implements standard JWT signing and verification.
	 * @param options optional pass-through options.
	 */
	async verifyAsync(jwtCryptoProvider: AsyncJWTCryptoProvider, options?: any): Promise<VerificationResult<SDJwt>> {
		const jwtVerificationResult = await jwtCryptoProvider.verifyAsync(this.jwt, options);

		return defaultVerificationResult(
			this,
			jwtVerificationResult.verified,
			jwtVerificationResult.verified && this.sdPayload.verifyDisclosures(),
			jwtVerificationResult.message
		);
	}

	/**
	 * Parse SD-JWT from string.
	 * @param sdJwt SD-JWT string to parse.
	 */
	static parse(sdJwt: string): SDJwt {
		const match =
			sdJwt.match(SDJwt.SD_JWT_PATTERN) ||
			(function () {
				throw new Error('Invalid SD-JWT');
			})();
		const header = JSON.parse(toString(fromString(match.groups!.header!, 'base64'), 'utf-8'));
		const disclosures = new Set(match.groups!.disclosures?.replace(/^~+|~+$/g, '')?.split(SDJwt.SEPARATOR) || []);
		const holderJwt = match.groups!.holderjwt;
		const sdPayload = SDPayload.parse(match.groups!.body!, disclosures);
		return new SDJwt(sdJwt, header, sdPayload, holderJwt);
	}

	/**
	 * Parse SD-JWT from string and verify it.
	 * @param sdJwt SD-JWT string to parse and verify.
	 * @param jwtCryptoProvider synchronous JWT crypto provider to use for signature verification, that implements standard JWT signing and verification.
	 * @param options optional pass-through options.
	 */
	static parseAndVerify(sdJwt: string, jwtCryptoProvider: JWTCryptoProvider, options?: any): VerificationResult<SDJwt> {
		return SDJwt.parse(sdJwt).verify(jwtCryptoProvider, options);
	}

	/**
	 * Parse SD-JWT from string and verify it.
	 * @param sdJwt SD-JWT string to parse and verify.
	 * @param jwtCryptoProvider asynchronous JWT crypto provider to use for signature verification, that implements standard JWT signing and verification.
	 * @param options optional pass-through options.
	 */
	static async parseAndVerifyAsync(
		sdJwt: string,
		jwtCryptoProvider: AsyncJWTCryptoProvider,
		options?: any
	): Promise<VerificationResult<SDJwt>> {
		return await SDJwt.parse(sdJwt).verifyAsync(jwtCryptoProvider, options);
	}

	private static createFromSignedJWT(signedJwt: string, sdPayload: SDPayload, withHolderJwt?: string | null): SDJwt {
		const sdJwt = SDJwt.parse(signedJwt);
		return new SDJwt(signedJwt, sdJwt.header, sdPayload, withHolderJwt);
	}

	/**
	 * Sign given payload as SD-JWT, using given JWT crypto provider, with optional key ID and pass-through options.
	 * @param sdPayload payload with selective disclosures to sign.
	 * @param jwtCryptoProvider synchronous JWT crypto provider to use for signing, that implements standard JWT signing and verification.
	 * @param keyId optional key ID of the signing key to be used, if required by the underlying crypto library.
	 * @param withHolderJwt optional holder JWT as holder binding to include in the SD-JWT.
	 * @param options optional pass-through options.
	 */
	static sign(
		sdPayload: SDPayload,
		jwtCryptoProvider: JWTCryptoProvider,
		keyId: string | undefined | null = null,
		withHolderJwt: string | undefined | null = null,
		typ: string = 'JWT',
		options?: any
	): SDJwt {
		return SDJwt.createFromSignedJWT(
			jwtCryptoProvider.sign(sdPayload.undisclosedPayload, keyId, typ, options),
			sdPayload,
			withHolderJwt
		);
	}

	/**
	 * Sign given payload as SD-JWT, using given JWT crypto provider, with optional key ID and pass-through options.
	 * @param sdPayload payload with selective disclosures to sign.
	 * @param jwtCryptoProvider asynchronous JWT crypto provider to use for signing, that implements standard JWT signing and verification.
	 * @param keyId optional key ID of the signing key to be used, if required by the underlying crypto library.
	 * @param withHolderJwt optional holder JWT as holder binding to include in the SD-JWT.
	 * @param options optional pass-through options.
	 */
	static async signAsync(
		sdPayload: SDPayload,
		jwtCryptoProvider: AsyncJWTCryptoProvider,
		keyId: string | undefined | null = null,
		withHolderJwt: string | undefined | null = null,
		options?: any
	): Promise<SDJwt> {
		return SDJwt.createFromSignedJWT(
			await jwtCryptoProvider.signAsync(sdPayload.undisclosedPayload, keyId, options),
			sdPayload,
			withHolderJwt
		);
	}

	/**
	 * Check whether given JWT is an SD-JWT.
	 * @param value JWT to check.
	 */
	static isSDJwt(value: string): boolean {
		return value.match(SDJwt.SD_JWT_PATTERN) !== null;
	}
}
