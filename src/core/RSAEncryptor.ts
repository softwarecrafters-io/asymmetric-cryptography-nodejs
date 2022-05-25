import * as crypto from 'crypto';

export class RSAEncryptor {
	private constructor(
		readonly encoding = 'binary' as BufferEncoding,
		readonly hash = 'sha256',
		readonly padding = crypto.constants.RSA_PKCS1_OAEP_PADDING
	) {}

	static create() {
		return new RSAEncryptor();
	}

	encrypt(publicKey: string, plainText: string) {
		const keyOptions = {
			key: publicKey,
			padding: this.padding,
			oaepHash: this.hash,
		};
		const buffer = this.fromBufferToString(plainText);
		return crypto.publicEncrypt(keyOptions, buffer).toString(this.encoding);
	}

	decrypt(privateKey: string, ciphertext: string) {
		const keyOptions = {
			key: privateKey,
			padding: this.padding,
			oaepHash: this.hash,
		};
		const buffer = this.fromBufferToString(ciphertext);
		return crypto.privateDecrypt(keyOptions, buffer).toString(this.encoding);
	}

	private fromBufferToString(plainText: string) {
		return Buffer.from(plainText, this.encoding);
	}
}
