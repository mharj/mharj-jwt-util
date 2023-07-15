// http://stackoverflow.com/questions/18835132/xml-to-pem-in-node-js

export function rsaPublicKeyPem(modulusB64: string, exponentB64: string) {
	const modulus = Buffer.from(modulusB64, 'base64');
	const exponent = Buffer.from(exponentB64, 'base64');

	let modulusHex = modulus.toString('hex');
	let exponentHex = exponent.toString('hex');

	modulusHex = prepadSigned(modulusHex);
	exponentHex = prepadSigned(exponentHex);

	const modlen = modulusHex.length / 2;
	const explen = exponentHex.length / 2;

	const encodedModlen = encodeLengthHex(modlen);
	const encodedExplen = encodeLengthHex(explen);
	const encodedPubkey =
		'30' +
		encodeLengthHex(modlen + explen + encodedModlen.length / 2 + encodedExplen.length / 2 + 2) +
		'02' +
		encodedModlen +
		modulusHex +
		'02' +
		encodedExplen +
		exponentHex;

	return Buffer.from(encodedPubkey, 'hex').toString('base64');
}

export function buildCertFrame(der: string | Buffer): Buffer | string {
	if (!Buffer.isBuffer(der)) {
		return der;
	}
	const match = der.toString().match(/.{1,64}/g);
	if (!match) {
		throw new Error('Cert data error');
	}
	return Buffer.from('-----BEGIN RSA PUBLIC KEY-----\r\n' + match.join('\r\n') + '\r\n-----END RSA PUBLIC KEY-----\r\n');
}

function prepadSigned(hexStr: string) {
	const msb = hexStr[0];
	if (msb < '0' || msb > '7') {
		return '00' + hexStr;
	} else {
		return hexStr;
	}
}

function toHex(numberValue: number) {
	const nstr = numberValue.toString(16);
	if (nstr.length % 2) {
		return '0' + nstr;
	}
	return nstr;
}

// encode ASN.1 DER length field
// if <=127, short form
// if >=128, long form
function encodeLengthHex(n: number) {
	if (n <= 127) {
		return toHex(n);
	} else {
		const nHex = toHex(n);
		const lengthOfLengthByte = 128 + nHex.length / 2; // 0x80+numbytes
		return toHex(lengthOfLengthByte) + nHex;
	}
}
