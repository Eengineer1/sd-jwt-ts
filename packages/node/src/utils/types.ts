import { SDJwt } from '../SDJwt.js';

export type JSONPrimitive = string | number | boolean | null;
export type JSONValue = JSONPrimitive | JSONObject | JSONArray;
export type JSONObject = { [key: string]: JSONValue };
export type JSONArray = JSONValue[];
export type JSONWebKey = {
	alg?: string;
	crv?: string;
	e?: string;
	ext?: boolean;
	key_ops?: string[];
	kid?: string;
	kty: string;
	n?: string;
	use?: string;
	x?: string;
	y?: string;
	[key: string]: any;
};
export type UndisclosedPayload = JSONObject & { [SDJwt.DIGESTS_KEY]?: string[]; [SDJwt.DIGESTS_ALG_KEY]?: 'sha-256' };
export type UndisclosedPayloadWithDigests = UndisclosedPayload & { [SDJwt.DIGESTS_KEY]: string[] };
export type UndisclosedPayloadWithDigestsAndAlg = UndisclosedPayload & {
	[SDJwt.DIGESTS_KEY]: string[];
	[SDJwt.DIGESTS_ALG_KEY]: 'sha-256';
};
