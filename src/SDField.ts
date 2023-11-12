import { SDMap } from './SDMap.js';

export class SDField {
	constructor(
		public readonly sd: boolean,
		public readonly children: SDMap | null = null
	) {}

	toJSON() {
		return JSON.stringify({
			sd: this.sd,
			children: this.children ? this.children.toJSON() : null,
		});
	}

	static fromJSON(json: string): SDField {
		const { sd, children } = JSON.parse(json);
		return new SDField(sd, children ? SDMap.fromJSON(children) : null);
	}
}
