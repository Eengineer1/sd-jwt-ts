import { JWTVerificationResult } from './VerificationResult.js';

/**
 * A synchronous JWT crypto provider, that can be used to sign and verify SD-JWTs.
 * Allows for the use of synchronous signing and verification algorithms, by integrating with any JWT crypto library.
 */
export interface JWTCryptoProvider {
	/**
	 * Interface method to create a signed JWT for the given JSON payload object, with an optional key ID and pass-through options.
	 * @param payload the JSON payload of the JWT to be signed.
	 * @param keyId optional key ID of the signing key to be used, if required by the underlying crypto library.
	 * @param options optional pass-through options to be used by the underlying crypto library, if applicable.
	 */
	sign(payload: any, keyId?: string | null, typ?: string, options?: any): string;

	/**
	 * Interface method for verifying a JWT signature, with an optional set of pass-through options.
	 * @param jwt Signed JWT to be verified.
	 * @param options optional pass-through options to be used by the underlying crypto library, if applicable.
	 */
	verify(jwt: string, options?: any): JWTVerificationResult;
}
