import { JWTVerificationResult } from './VerificationResult.js';
import { JSONObject } from './utils/types.js';

/**
 * An asynchronous JWT crypto provider, that can be used to sign and verify SD-JWTs.
 * Allows for the use of asynchronous signing and verification algorithms, by integrating with any JWT crypto library.
 */
export interface AsyncJWTCryptoProvider {
	/**
	 * Interface method to create a signed JWT for the given JSON payload object, with an optional key ID and pass-through options.
	 * @param payload the JSON payload of the JWT to be signed.
	 * @param keyId optional key ID of the signing key to be used, if required by the underlying crypto library.
	 * @param options optional pass-through options to be used by the underlying crypto library, if applicable.
	 */
	signAsync(payload: JSONObject, keyId?: string | null, options?: any): Promise<string>;

	/**
	 * Interface method for verifying a JWT signature, with an optional set of pass-through options.
	 * @param jwt Signed JWT to be verified.
	 * @param options optional pass-through options to be used by the underlying crypto library, if applicable.
	 */
	verifyAsync(jwt: string, options?: any): Promise<JWTVerificationResult>;
}
