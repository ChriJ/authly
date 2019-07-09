import { crypto } from "../crypto"
import { Symmetric } from "./Symmetric"
import { Name } from "./Name"

export class HS256 extends Symmetric {
	get name(): Name { return "HS256" }
	private key: PromiseLike<CryptoKey>
	constructor(key: Uint8Array | string) {
		super()
		this.key = crypto.subtle.importKey("raw", this.encodeKey(key), { name: "HMAC", hash: { name: "SHA-256" } }, false, [ "sign", "verify" ])
	}
	async signBinary(data: Uint8Array): Promise<Uint8Array> {
		return new Uint8Array(await crypto.subtle.sign("HMAC", await this.key, data))
	}
}
