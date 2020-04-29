# mharj-jwt-util

## Json Webtoken Utility to validate OpenID tokens against issuer public ssl keys

- Can build public PEM cert from modulus + exponent (i.e. Google)
- Utilizes cross-fetch polyfill for loading issuer discovery configuration and "jwks_uri" data, so should work on most of JS platforms
- Caches issuer OpenID configuration 24h
- New Token "kid" forces reloading jwks_uri data.

## Usage example

```javascript
// with async
try {
	const decoded = await jwtBearerVerify(req.headers.authorization);
} catch (err) {
	console.log(err);
}
// or Promised
jwtBearerVerify(req.headers.authorization)
	.then((decoded) => {
		// do something
	})
	.catch((err) => {
		console.log(err);
	});
// or Just token
try {
	const decode = await jwtVerify(process.env.GOOGLE_ID_TOKEN);
} catch (err) {
	console.log(err);
}

// or Promised token
jwtVerify(process.env.GOOGLE_ID_TOKEN)
	.then((decoded) => {
		// do something
	})
	.catch((err) => {
		console.log(err);
	});
```
