import * as crypto from 'crypto';

export class KeyPairGenerator {
	private constructor(private privateKey: crypto.KeyObject, private publicKey: crypto.KeyObject) {}

	static generate() {
		const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
			// The standard secure default length for RSA keys is 2048 bits
			modulusLength: 2048,
		});
		return new KeyPairGenerator(privateKey, publicKey);
	}

	exportPublicKey() {
		return this.publicKey
			.export({
				type: 'pkcs1',
				format: 'pem',
			})
			.toString();
	}

	exportPrivateKey() {
		return this.privateKey
			.export({
				type: 'pkcs1',
				format: 'pem',
			})
			.toString();
	}
}
