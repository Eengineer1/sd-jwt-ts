import { JSONObject } from './types.js';

export function isJSONObject(obj: any): obj is JSONObject {
	return obj && typeof obj === 'object' && !Array.isArray(obj);
}

export function isSDDigestsValue(value: any): value is string[] {
	return Array.isArray(value) && value.every((v) => typeof v === 'string');
}
