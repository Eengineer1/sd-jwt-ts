import { JWTVerifyOptions, KeyLike, SignJWT, SignOptions, jwtVerify } from 'jose';
import { AsyncJWTCryptoProvider } from '../AsyncJWTCryptoProvider.js';
import { JSONObject } from '../utils/types.js';
import { JWTVerificationResult } from '../VerificationResult.js';

export class CompactAsyncJWTCryptoProvider implements AsyncJWTCryptoProvider {
	constructor(
		private readonly algorithm: string,
		private readonly keyParam: KeyLike | Uint8Array,
		private readonly signOptions?: SignOptions,
		private readonly verifyOptions?: JWTVerifyOptions
	) {}

	async signAsync(payload: JSONObject, keyId?: string | null): Promise<string> {
		const jwt = await new SignJWT(payload)
			.setProtectedHeader({ alg: this.algorithm, kid: keyId || undefined, typ: 'JWT' })
			.sign(this.keyParam, this.signOptions);
		return jwt;
	}

	async verifyAsync(jwt: string): Promise<JWTVerificationResult> {
		try {
			await jwtVerify(jwt, this.keyParam, this.verifyOptions);
			return {
				verified: true,
			} satisfies JWTVerificationResult;
		} catch (error) {
			return {
				verified: false,
				message: (error as Error).message,
			} satisfies JWTVerificationResult;
		}
	}
}
