import { DecoyMode } from '../src/DecoyMode';
import { SDField } from '../src/SDField';
import { SDJwt } from '../src/SDJwt';
import { SDMap } from '../src/SDMap';
import { SDPayload } from '../src/SDPayload';
import { isJSONObject } from '../src/utils/eval';
import { JSONValue, UndisclosedPayloadWithDigests } from '../src/utils/types';
import { sdJwtValid } from './utils/testutils.test';

describe('SDJwt', () => {
	it('should parse a valid SD-JWT', () => {
		const sdJwt = SDJwt.parse(sdJwtValid);

		expect(sdJwt.undisclosedPayload).toBeDefined();
		expect(sdJwt.undisclosedPayload).toHaveProperty('sub');
		expect(sdJwt.undisclosedPayload).toHaveProperty('vc');
		expect(sdJwt.undisclosedPayload?.['vc']).toHaveProperty(SDJwt.DIGESTS_KEY);
		expect(sdJwt.undisclosedPayload?.['vc']).not.toHaveProperty('credentialSubject');

		expect(sdJwt.fullPayload?.['vc']).toHaveProperty('credentialSubject');
	});

	it('should generate a valid SD-JWT', () => {
		const fullPayload = {
			sub: '1234',
			nestedObject: {
				arrProp: ['item 1', 'item 2'],
			},
		};

		const sdPayload1 = SDPayload.createSDPayloadFromFullAndUndisclosedPayload(fullPayload, {});

		expect(sdPayload1.undisclosedPayload).toHaveProperty(SDJwt.DIGESTS_KEY);
		expect(sdPayload1.undisclosedPayload).toHaveProperty(SDJwt.DIGESTS_ALG_KEY);
		expect(sdPayload1.undisclosedPayload).not.toHaveProperty('sub', 'nestedObject');
		expect(sdPayload1.fullPayload).toEqual(fullPayload);
		expect((sdPayload1.undisclosedPayload[SDJwt.DIGESTS_KEY] as string[]).length).toBe(
			sdPayload1.digestedDisclosures.size
		);

		const sdPayload2 = SDPayload.createSDPayloadFromFullAndUndisclosedPayload(fullPayload, { nestedObject: {} });

		expect(sdPayload2.undisclosedPayload).toHaveProperty(SDJwt.DIGESTS_KEY);
		expect(sdPayload2.undisclosedPayload).toHaveProperty(SDJwt.DIGESTS_ALG_KEY);
		expect(sdPayload2.undisclosedPayload).toHaveProperty('nestedObject');
		expect(sdPayload2.undisclosedPayload).not.toHaveProperty('sub');
		expect(sdPayload2.undisclosedPayload?.['nestedObject']).toHaveProperty(SDJwt.DIGESTS_KEY);
		expect(sdPayload2.undisclosedPayload?.['nestedObject']).toHaveProperty(SDJwt.DIGESTS_ALG_KEY);
		expect(sdPayload2.undisclosedPayload?.['nestedObject']).not.toHaveProperty('arrProp');
		expect(sdPayload2.fullPayload).toEqual(fullPayload);
		expect(
			sdPayload2.undisclosedPayload[SDJwt.DIGESTS_KEY]!.length +
				(sdPayload2.undisclosedPayload?.['nestedObject'] as UndisclosedPayloadWithDigests)[SDJwt.DIGESTS_KEY]
					.length
		).toBe(sdPayload2.digestedDisclosures.size);

		const sdPayload3 = SDPayload.createSDPayload(
			fullPayload,
			new SDMap(
				new Map([
					['sub', new SDField(true)],
					['nestedObject', new SDField(true, new SDMap(new Map([['arrProp', new SDField(true)]])))],
				])
			)
		);

		expect(sdPayload3.undisclosedPayload).toHaveProperty(SDJwt.DIGESTS_KEY);
		expect(sdPayload3.undisclosedPayload).toHaveProperty(SDJwt.DIGESTS_ALG_KEY);
		expect(sdPayload3.undisclosedPayload).not.toHaveProperty('sub', 'nestedObject');

		const nestedDisclosure = sdPayload3.sDisclosures.find(
			(sd) => sd.key === 'nestedObject' && isJSONObject(sd.value)
		);

		expect(nestedDisclosure).toBeDefined();
		expect(nestedDisclosure!.value).toHaveProperty(SDJwt.DIGESTS_KEY);
		expect(nestedDisclosure!.value).toHaveProperty(SDJwt.DIGESTS_ALG_KEY);
		expect(nestedDisclosure!.value).not.toHaveProperty('arrProp');
		expect(sdPayload3.fullPayload).toEqual(fullPayload);
		expect(
			sdPayload3.undisclosedPayload[SDJwt.DIGESTS_KEY]!.length +
				(nestedDisclosure!.value as UndisclosedPayloadWithDigests)[SDJwt.DIGESTS_KEY].length
		).toBe(sdPayload3.digestedDisclosures.size);
	});

	it('should generate a valid SD-JWT with decoys', () => {
		const fullPayload = {
			sub: '1234',
			nestedObject: {
				arrProp: ['item 1', 'item 2'],
			},
		};

		const sdPayload1 = SDPayload.createSDPayload(
			fullPayload,
			new SDMap(
				new Map([
					['sub', new SDField(true)],
					[
						'nestedObject',
						new SDField(true, new SDMap(new Map([['arrProp', new SDField(true)]]), DecoyMode.FIXED, 5)),
					],
				]),
				DecoyMode.RANDOM,
				5
			)
		);

		expect(sdPayload1.undisclosedPayload).toHaveProperty(SDJwt.DIGESTS_KEY);
		expect(sdPayload1.undisclosedPayload).toHaveProperty(SDJwt.DIGESTS_ALG_KEY);
		expect(sdPayload1.undisclosedPayload).not.toHaveProperty('sub', 'nestedObject');

		const nestedDisclosure = sdPayload1.sDisclosures.find(
			(sd) => sd.key === 'nestedObject' && isJSONObject(sd.value)
		);

		expect(nestedDisclosure).toBeDefined();
		expect(nestedDisclosure!.value).toHaveProperty(SDJwt.DIGESTS_KEY);
		expect(nestedDisclosure!.value).toHaveProperty(SDJwt.DIGESTS_ALG_KEY);
		expect(nestedDisclosure!.value).not.toHaveProperty('arrProp');

		const numSdFieldsTopLevel = Array.from(sdPayload1.sdMap.values()).filter((sdField) => sdField.sd).length;

		expect(sdPayload1.undisclosedPayload[SDJwt.DIGESTS_KEY]!.length).toBeGreaterThanOrEqual(
			numSdFieldsTopLevel + 1
		);
		expect(sdPayload1.undisclosedPayload[SDJwt.DIGESTS_KEY]!.length).toBeLessThanOrEqual(numSdFieldsTopLevel + 5);

		const numSdFieldsNestedLevel = Array.from(sdPayload1.sdMap.get('nestedObject')!.children!.values()).filter(
			(sdField) => sdField.sd
		).length;

		expect((nestedDisclosure!.value as UndisclosedPayloadWithDigests)[SDJwt.DIGESTS_KEY].length).toBe(
			numSdFieldsNestedLevel + 5
		);
	});

	it('should generate SDMap from JSON paths', () => {
		const sdMap1 = SDMap.generateSDMapFromJSONPaths(['credentialSubject', 'credentialSubject.firstName']);

		expect(sdMap1.get('credentialSubject')).toBeDefined();
		expect(sdMap1.get('credentialSubject')!.sd).toBe(true);
		expect(sdMap1.get('credentialSubject')!.children).toBeTruthy();
		expect(sdMap1.get('credentialSubject')!.children!.has('firstName')).toBe(true);
		expect(sdMap1.get('credentialSubject')!.children!.get('firstName')!.sd).toBe(true);

		const sdMap2 = SDMap.generateSDMapFromJSONPaths(['credentialSubject.firstName']);

		expect(sdMap2.get('credentialSubject')).toBeDefined();
		expect(sdMap2.get('credentialSubject')!.sd).toBe(false);
		expect(sdMap2.get('credentialSubject')!.children).toBeTruthy();
		expect(sdMap2.get('credentialSubject')!.children!.has('firstName')).toBe(true);
		expect(sdMap2.get('credentialSubject')!.children!.get('firstName')!.sd).toBe(true);
	});
});
