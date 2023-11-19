import { DecoyMode, fromJSON as DecoyModefromJSON } from './DecoyMode.js';
import { SDField } from './SDField.js';
import { SDJwt } from './SDJwt.js';
import { SDisclosure } from './SDisclosure.js';
import { isJSONObject } from './utils/eval.js';
import { JSONObject, JSONValue, UndisclosedPayload } from './utils/types.js';

export class SDMap extends Map<string, SDField> {
	private readonly _size: number;
	get size() {
		return this._size;
	}
	constructor(
		public readonly fields: ReadonlyMap<string, SDField>,
		public readonly decoyMode: DecoyMode = DecoyMode.NONE,
		public readonly decoys: number = 0
	) {
		super();
		this._size = fields.size;
		this.entries = fields.entries.bind(fields);
		this.keys = fields.keys.bind(fields);
		this.values = fields.values.bind(fields);
		this.get = fields.get.bind(fields);
		this.has = fields.has.bind(fields);
		this[Symbol.iterator] = fields[Symbol.iterator].bind(fields);

		this.set = function (key: string, value: any) {
			throw new Error('SDMap is immutable');
		};
		this.delete = function (key: string) {
			throw new Error('SDMap is immutable');
		};
		this.clear = function () {
			throw new Error('SDMap is immutable');
		};
	}

	prettyPrint() {
		return JSON.stringify(this, null, 2);
	}

	toJSON() {
		return {
			fields: this.fields.size ? Object.fromEntries(this.fields) : null,
			decoyMode: this.decoyMode.valueOf(),
			decoys: this.decoys,
		} as const;
	}

	/**
	 * Generate SDMap by comparing the fully disclosed payload with the undisclosed payload.
	 */
	static generateSDMap(
		fullPayload: JSONObject,
		undisclosedPayload: JSONObject,
		decoyMode: DecoyMode = DecoyMode.NONE,
		decoys: number = 0
	): SDMap {
		const fields = new Map<string, SDField>();
		for (const [key, value] of Object.entries(fullPayload)) {
			const sd = typeof undisclosedPayload?.[key] === 'undefined' || !(key in undisclosedPayload);
			fields.set(
				key,
				new SDField(
					sd,
					value && isJSONObject(value) && undisclosedPayload[key] && isJSONObject(undisclosedPayload[key])
						? SDMap.generateSDMap(value, undisclosedPayload[key]! as JSONObject, decoyMode, decoys)
						: null
				)
			);
		}
		return new SDMap(fields, decoyMode, decoys);
	}

	/**
	 * Generate SDMap based on set of simplified JSON paths.
	 */
	static generateSDMapFromJSONPaths(jsonPaths: string[], decoyMode: DecoyMode = DecoyMode.NONE, decoys: number = 0) {
		return SDMap.doGenerateSDMap(jsonPaths, decoyMode, decoys, new Set(jsonPaths), '');
	}

	private static doGenerateSDMap(
		jsonPaths: string[],
		decoyMode: DecoyMode = DecoyMode.NONE,
		decoys: number,
		sdPaths: Set<string>,
		parent: string
	): SDMap {
		const pathMap = jsonPaths
			.map((path) => {
				const [first, ...rest] = path.split('.');

				if (!first) throw new Error('Invalid JSON path');

				if (rest.length === 0) return { first, second: '' };

				return { first, second: rest.join('.') };
			})
			.reduce((acc, { first, second }) => {
				if (!acc.has(first)) acc.set(first, []);

				if (second) acc.set(first, [...acc.get(first)!, second]);

				return acc;
			}, new Map<string, string[]>());

		const fields = Array.from(pathMap.entries()).reduce((acc, [key, value]) => {
			const currentPath = [parent, key].filter(Boolean).join('.');
			acc.set(
				key,
				new SDField(
					sdPaths.has(currentPath),
					value.length ? SDMap.doGenerateSDMap(value, decoyMode, decoys, sdPaths, currentPath) : null
				)
			);
			return acc;
		}, new Map<string, SDField>());

		return new SDMap(fields, decoyMode, decoys);
	}

	private static regenerateSDField(
		sd: boolean,
		value: JSONValue,
		digestedDisclosure: ReadonlyMap<string, SDisclosure>
	): SDField {
		return new SDField(sd, value && isJSONObject(value) ? SDMap.regenerateSDMap(value, digestedDisclosure) : null);
	}

	/**
	 * Regenerate SDMap recursively, from undisclosed payload and digested disclosures map.
	 * Used for parsing SD-JWTs.
	 */
	static regenerateSDMap(
		undisclosedPayload: UndisclosedPayload,
		digestedDisclosures: ReadonlyMap<string, SDisclosure>
	): SDMap {
		return new SDMap(
			new Map<string, SDField>(
				(
					undisclosedPayload[SDJwt.DIGESTS_KEY]
						?.filter((sdEntry) => Array.from(digestedDisclosures.values()).find((sd) => sd.key === sdEntry))
						?.map((sdEntry) => Array.from(digestedDisclosures.values()).find((sd) => sd.key === sdEntry)!)
						?.map(
							(sd) => [sd.key, SDMap.regenerateSDField(true, sd.value, digestedDisclosures)] as const
						) || []
				).concat(
					Object.entries(undisclosedPayload)
						.filter(([key]) => key !== SDJwt.DIGESTS_KEY)
						.map(
							([key, value]) => [key, SDMap.regenerateSDField(false, value, digestedDisclosures)] as const
						)
				)
			),
			DecoyMode.FIXED, // parse will always be called with a decoyMode of FIXED, as number of decoys is known
			undisclosedPayload[SDJwt.DIGESTS_KEY]?.filter(
				(sdEntry) => !Array.from(digestedDisclosures.values()).find((sd) => sd.key === sdEntry)
			)?.length || 0
		);
	}

	static fromJSON(json: JSONObject): SDMap {
		return new SDMap(
			new Map<string, SDField>(
				Object.entries(json?.['fields'] ?? new Map<string, SDField>()).map(([key, value]) => [
					key,
					SDField.fromJSON(value),
				]) as [string, SDField][]
			),
			json?.['decoyMode'] ? DecoyModefromJSON(json['decoyMode']) : DecoyMode.NONE,
			typeof json?.['decoys'] === 'number' ? json['decoys'] : 0
		);
	}

	static fromJSONString(json: string): SDMap {
		return SDMap.fromJSON(JSON.parse(json));
	}
}
