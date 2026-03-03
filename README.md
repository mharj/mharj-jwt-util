# mharj-jwt-util

[![Build Status](https://mharj.visualstudio.com/mharj-jwt-util/_apis/build/status/mharj.mharj-jwt-util?branchName=master)](https://mharj.visualstudio.com/mharj-jwt-util/_build/latest?definitionId=3&branchName=master) ![Azure DevOps coverage](https://img.shields.io/azure-devops/coverage/mharj/mharj-jwt-util/3) [![Maintainability](https://api.codeclimate.com/v1/badges/a60873c223b5bafadb1f/maintainability)](https://codeclimate.com/github/mharj/mharj-jwt-util/maintainability)

## Json Webtoken Utility to validate OpenID tokens against issuer public ssl keys

- Can build public PEM cert from modulus + exponent (i.e. Google)
- Caches issuer OpenID configuration 24h
- New Token "kid" forces reloading jwks_uri data.

Note: if running NodeJS less than 18.0.0 you need to install and use cross-fetch polyfill

## Usage example

```javascript
// with Bearer header
try {
  const { body, isCached } = await jwtBearerVerify(req.headers.authorization);
} catch (err) {
  console.log(err);
}
// or Just token
try {
  const { body, isCached } = await jwtVerify(process.env.GOOGLE_ID_TOKEN);
} catch (err) {
  console.log(err);
}

// attach logger to see http requests (console and log4js should be working)
setJwtLogger(console);
```

## Enable public cert file caching

```javascript
const certCacheSchema = z.object({certs: z.record(z.string(), z.record(z.string(), z.string())), _ts: z.number()}) satisfies StandardSchemaV1<
	unknown,
	CertRecords
>;
await useCache(new FileCertCache({fileName: './certCache.json', schema: certCacheSchema}));

// or with Tachyon storage driver
await useCache(new TachyonCertCache(new FileStorageDriver({name: 'FileCertCacheDriver', fileName: './unitTestCache.json'}, certCacheBufferSerializer(certCacheSchema))));
```

## Enable verified token persist caching (Tachyon storage driver with encryption)

```typescript
import { z } from "zod";
import { TachyonExpireCache } from "tachyon-expire-cache";
import {
  CryptoBufferProcessor,
  FileStorageDriver,
} from "tachyon-drive-node-fs";
import { buildTokenCacheBufferSerializer, setTokenCache } from "mharj-jwt-util";

const tokenBodySchema = z.object({}).loose(); // or build token payload schema
const tokenCacheMapSchema = z.map(z.string().refine(isRawJwtToken), z.object({expires: z.number(), data: tokenBodySchema}));
const bufferSerializer = buildTokenCacheBufferSerializer(tokenCacheMapSchema);
// const stringSerializer = buildTokenCacheStringSerializer<TokenPayload>(tokenCacheMapSchema); // if using string based Tachyon drivers
const processor = new CryptoBufferProcessor(Buffer.from("some-secret-key"));
const driver = new FileStorageDriver({name: 'TokenStorageDriver', fileName: "./tokenCache.aes" }, bufferSerializer, processor);
const cache = new TachyonExpireCache<z.infer<typeof tokenBodySchema>, RawJwtToken>({name: 'TachyonExpireCache'}, driver);
setTokenCache(cache);
```
