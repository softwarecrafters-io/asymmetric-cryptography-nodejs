import { RSAEncryptor } from '../core/RSAEncryptor';
import { privateKey, publicKey } from './keys';
import { RSASigner } from '../core/RSASigner';

describe('The RSA signer', () => {
	const signer = RSASigner.create();

	it('signs a given text using a private key', () => {
		//given
		const message = 'hello world!';
		//when
		const signature = signer.sign(privateKey, message);
		//then
		expect(signature.length).toBe(256);
	});

	it('verifies a given signed text using a public key', () => {
		//given
		const message = 'hello world!';
		const signature = signer.sign(privateKey, message);
		//when
		const isVerified = signer.verify(publicKey, message, signature);
		//then
		expect(isVerified).toBe(true);
	});

	it('does not verify a given modified text using a public key', () => {
		//given
		const message = 'hello world!';
		const signature = signer.sign(privateKey, message);
		const modifiedMessage = 'hello world modified';
		//when
		const isVerified = signer.verify(publicKey, modifiedMessage, signature);
		//then
		expect(isVerified).toBe(false);
	});
});
