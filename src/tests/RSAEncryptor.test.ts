import { RSAEncryptor } from '../core/RSAEncryptor';
import { privateKey, publicKey } from './keys';

describe('The RSA encryptor', () => {
	const encryptor = RSAEncryptor.create();

	it('encrypts a given message using a public key', () => {
		//given
		const message = 'hello world!';
		//when
		const cipherMessage = encryptor.encrypt(publicKey, message);
		//then
		expect(cipherMessage.length).toBe(256);
		expect(cipherMessage).not.toContain(message);
	});

	it('decrypts a given cipher message using a private key', () => {
		//given
		const message = 'hello world!';
		const cipherMessage = encryptor.encrypt(publicKey, message);
		//when
		const decipherMessage = encryptor.decrypt(privateKey, cipherMessage);
		//then
		expect(decipherMessage).toBe(message);
	});
});
