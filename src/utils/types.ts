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
