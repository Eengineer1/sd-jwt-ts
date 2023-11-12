import { DecoyMode, fromJSON as DecoyModefromJSON } from './DecoyMode.js';
import { SDField } from './SDField.js';
import { SDJwt } from './SDJwt.js';
import { SDisclosure } from './SDisclosure.js';
import { JSONObject, JSONValue } from './utils/types.js';

export class SDMap extends Map<string, SDField> {
	readonly size: number;
	constructor(
		public readonly fields: ReadonlyMap<string, SDField>,
		public readonly decoyMode: DecoyMode = DecoyMode.NONE,
		public readonly decoys: number = 0
	) {
		super();
		this.size = fields.size;
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
			const sd = !Object.prototype.hasOwnProperty.call(undisclosedPayload, key);
			fields.set(
				key,
				new SDField(
					sd,
					value && typeof value === 'object' && !Array.isArray(value)
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
	generateSDMapFromJSONPaths(jsonPaths: string[], decoyMode: DecoyMode = DecoyMode.NONE, decoys: number = 0) {
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
			.map((path) => path.split('.'))
			.reduce((map, path) => {
				const key = path.shift()!;
				const value = path.join('.');
				return map.set(key, map.has(key) ? map.get(key)!.concat(value) : [value]);
			}, new Map<string, string[]>());

		const fields = new Map<string, SDField>();

		for (const [key, value] of pathMap.entries()) {
			const currentPath = parent ? `${parent}.${key}` : key;

			fields.set(
				key,
				new SDField(
					sdPaths.has(key),
					value.length ? SDMap.doGenerateSDMap(value, decoyMode, decoys, sdPaths, currentPath) : null
				)
			);
		}

		return new SDMap(fields, decoyMode, decoys);
	}

	private static regenerateSDField(
		sd: boolean,
		value: JSONValue,
		digestedDisclosure: ReadonlyMap<string, SDisclosure>
	): SDField {
		return new SDField(
			sd,
			value && typeof value === 'object' && !Array.isArray(value)
				? SDMap.regenerateSDMap(value, digestedDisclosure)
				: null
		);
	}

	/**
	 * Regenerate SDMap recursively, from undisclosed payload and digested disclosures map.
	 * Used for parsing SD-JWTs.
	 */
	static regenerateSDMap(
		undisclosedPayload: JSONObject,
		digestedDisclosures: ReadonlyMap<string, SDisclosure>
	): SDMap {
		return new SDMap(
			new Map<string, SDField>(
				(
					(
						Object.entries(undisclosedPayload)?.filter(([key]) => key === SDJwt.DIGESTS_KEY) as [
							string,
							string[],
						][]
					)
						?.flatMap(([, digests]) => digests)
						?.filter((sdEntry) => digestedDisclosures.has(sdEntry))
						?.map((sdEntry) => digestedDisclosures.get(sdEntry)!)
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
			)
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
