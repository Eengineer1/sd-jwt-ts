import { isJSONObject } from './utils/eval.js';
import { JSONValue } from './utils/types.js';

/**
 * Mode for adding decoy digests on SD-JWT issuance.
 * NONE: no decoy digests are added
 * FIXED: a fixed number of decoy digests are added
 * RANDOM: a random number of decoy digests are added
 */
export enum DecoyMode {
	NONE = 'NONE', // literal string value + ordinal value (0)
	FIXED = 'FIXED', // literal string value + ordinal value (1)
	RANDOM = 'RANDOM', // literal string value + ordinal value (2)
}

export const fromJSON = (json: JSONValue): DecoyMode => {
	if (isJSONObject(json)) {
		return typeof json?.['name']?.valueOf() === 'string'
			? (json['name'] as DecoyMode)
			: (function () {
					throw new Error('Invalid decoy mode');
			  })();
	}

	switch (json) {
		case DecoyMode.NONE:
		case DecoyMode.FIXED:
		case DecoyMode.RANDOM:
			return json;
		default:
			throw new Error('Invalid decoy mode');
	}
};
