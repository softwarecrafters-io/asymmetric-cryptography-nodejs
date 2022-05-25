import * as crypto from 'crypto';

export class RSASigner {
	private constructor(
		readonly encoding = 'binary' as BufferEncoding,
		readonly hash = 'sha256',
		readonly padding = crypto.constants.RSA_PKCS1_PSS_PADDING
	) {}

	static create() {
		return new RSASigner();
	}

	sign(privateKey: string, plainText: string): Buffer {
		const signature = crypto.sign(this.hash, Buffer.from(plainText, this.encoding), {
			key: privateKey,
			padding: this.padding,
		});
		return signature;
	}

	verify(publicKey: string, signedText: string, signature: Buffer) {
		const isVerified = crypto.verify(
			this.hash,
			this.fromStringToBuffer(signedText),
			{
				key: publicKey,
				padding: this.padding,
			},
			signature
		);
		return isVerified;
	}

	private fromStringToBuffer(signedText: string) {
		return Buffer.from(signedText, this.encoding);
	}
}
