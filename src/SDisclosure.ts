import { JSONValue } from './utils/types.js';
import { fromString, toString } from 'uint8arrays';

export class SDisclosure {
	constructor(
		public readonly disclosure: string,
		public readonly salt: string,
		public readonly key: string,
		public readonly value: JSONValue
	) {}

	static parse(disclosure: string): SDisclosure {
		const [salt, key, value] = JSON.parse(toString(fromString(disclosure, 'base64url'), 'utf-8')) as [
			string,
			string,
			JSONValue,
		];

		if (
			typeof salt !== 'string' ||
			typeof key !== 'string' ||
			(typeof value !== 'object' &&
				typeof value !== 'string' &&
				typeof value !== 'number' &&
				typeof value !== 'boolean')
		) {
			throw new Error('Invalid selective disclosure');
		}

		return new SDisclosure(disclosure, salt, key, value);
	}
}
