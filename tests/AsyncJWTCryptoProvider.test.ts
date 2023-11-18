import { fromString } from 'uint8arrays';
import { CompactAsyncJWTCryptoProvider } from '../src/providers/CompactAsyncJWTCryptoProvider';
import { sdJwtInvalid, sharedSecret } from './utils/testutils.test';
import { SDPayload } from '../src/SDPayload';
import { SDJwt } from '../src/SDJwt';

describe('AsyncJWTCryptoProvider', () => {
	it('should create, sign and verify SD-JWT', async () => {
		// instantiate JWT crypto provider
		const jwtCryptoProvider = new CompactAsyncJWTCryptoProvider('HS256', fromString(sharedSecret, 'utf-8'));

		// define claimset
		const originalClaimset = { sub: '123', aud: '456' };

		// define undisclosed claimset
		const undisclosedClaimset = { aud: '456' };

		// create SD payload
		const sdPayload = SDPayload.createSDPayloadFromFullAndUndisclosedPayload(originalClaimset, undisclosedClaimset);

		// create + sign JWT
		const sdJwt = await SDJwt.signAsync(sdPayload, jwtCryptoProvider);

		expect(sdJwt.undisclosedPayload).not.toHaveProperty('sub');
		expect(sdJwt.undisclosedPayload).toHaveProperty(SDJwt.DIGESTS_KEY);
		expect(sdJwt.undisclosedPayload).toHaveProperty('aud');
		expect(sdJwt.undisclosedPayload[SDJwt.DIGESTS_KEY]?.length).toBe(1);
		expect(sdJwt.disclosures.size).toBe(1);
		expect(sdJwt.undisclosedPayload[SDJwt.DIGESTS_KEY]![0]!).toBe('sub');
		expect(Array.from(sdJwt.digestedDisclosures.values())[0]!.key).toBe('sub');
		expect(sdJwt.fullPayload).toEqual(originalClaimset);

		// verify JWT
		const verificationResult = await sdJwt.verifyAsync(jwtCryptoProvider);

		expect(verificationResult.verified).toBe(true);

		// verify invalid JWT
		const invalidJwt = SDJwt.parse(sdJwtInvalid);
		const invalidVerificationResult = await invalidJwt.verifyAsync(jwtCryptoProvider);

		expect(invalidVerificationResult.verified).toBe(false);
	});
});
