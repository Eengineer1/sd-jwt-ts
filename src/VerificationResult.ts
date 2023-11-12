import { SDJwt } from './SDJwt.js';

export type JWTVerificationResult = {
	verified: boolean;
	message?: string | null;
};

export type VerificationResult<T = SDJwt> = {
	sdJwt: T;
	signatureVerified: boolean;
	disclosuresVerified: boolean;
	verified: boolean;
	message?: string | null;
};

export const defaultVerificationResult = (
	sdJwt: SDJwt,
	signatureVerified: boolean,
	disclosuresVerified: boolean,
	message?: string | null
): VerificationResult => {
	return {
		sdJwt,
		signatureVerified,
		disclosuresVerified,
		message,
		verified: signatureVerified && disclosuresVerified,
	};
};
