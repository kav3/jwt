declare const Buffer: any
import { createSign, createHmac, createVerify, randomBytes } from 'crypto'

const algorithmMap: {
  [key: string]: string
} = {
  HS256: 'sha256',
  HS384: 'sha384',
  HS512: 'sha512',
  RS256: 'RSA-SHA256'
}

const typeMap: {
  [key: string]: string
} = {
  HS256: 'hmac',
  HS384: 'hmac',
  HS512: 'hmac',
  RS256: 'sign'
}

export const random = async () => {
  return (await randomBytes(48)).toString('hex')
}
export const encode = (payload: any, key: string, algorithm = "HS256") => {
  if (!key) {
    throw new Error('Require key');
  }

  const signingMethod = algorithmMap[algorithm];
  const signingType = typeMap[algorithm];
  if (!signingMethod || !signingType) {
    throw new Error('Algorithm not supported');
  }

  // header, typ is fixed value.
  var header = { typ: 'JWT', alg: algorithm };
  // create segments, all segments should be base64 string
  var segments = [];
  segments.push(base64urlEncode(JSON.stringify(header)));
  segments.push(base64urlEncode(JSON.stringify(payload)));
  segments.push(sign(segments.join('.'), key, signingMethod, signingType));

  return segments.join('.');
}
const base64urlUnescape = (str: string) => {
  str += new Array(5 - str.length % 4).join('=');
  return str.replace(/\-/g, '+').replace(/_/g, '/');
}
const base64urlEncode = (str: string) => {
  return base64urlEscape(Buffer.from(str).toString('base64'));
}
const base64urlEscape = (str: string) => {
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
const base64urlDecode = (str: string) => {
  return Buffer.from(base64urlUnescape(str), 'base64').toString();
}
export const decode = (token: any, key: string, noVerify?: boolean, algorithm?: string) => {
  // check token
  if (!token) {
    throw new Error('No token supplied');
  }
  // check segments
  var segments = token.split('.');
  if (segments.length < 3) {
    throw new Error('Not enough or too many segments');
  }

  // All segment should be base64
  var headerSeg = segments[0].replace("Bearer ", "");
  var payloadSeg = segments[1];
  var signatureSeg = segments[2];

  // base64 decode and parse JSON
  var header = JSON.parse(base64urlDecode(headerSeg));
  var payload = JSON.parse(base64urlDecode(payloadSeg));

  if (!noVerify) {
    if (!algorithm && /BEGIN( RSA)? PUBLIC KEY/.test(key.toString())) {
      algorithm = 'RS256';
    }

    var signingMethod = algorithmMap[algorithm || header.alg];
    var signingType = typeMap[algorithm || header.alg];
    if (!signingMethod || !signingType) {
      throw new Error('Algorithm not supported');
    }

    // verify signature. `sign` will return base64 string.
    var signingInput = [headerSeg, payloadSeg].join('.');
    if (!verify(signingInput, key, signingMethod, signingType, signatureSeg)) {
      throw new Error('Signature verification failed');
    }

    // Support for nbf and exp claims.
    // According to the RFC, they should be in seconds.
    if (payload.nbf && Date.now() < payload.nbf * 1000) {
      throw new Error('Token not yet active');
    }

    if (payload.exp && Date.now() > payload.exp * 1000) {
      throw new Error('Token expired');
    }
  }

  return payload;
}
const sign = (input: any, key: string, method: string, type: any) => {
  var base64str;
  if (type === "hmac") {
    base64str = createHmac(method, key).update(input).digest('base64');
  }
  else if (type == "sign") {
    base64str = createSign(method).update(input).sign(key, 'base64');
  }
  else {
    throw new Error('Algorithm type not recognized');
  }

  return base64urlEscape(base64str);
}
const verify = (input: any, key: string, method: string, type: any, signature: any) => {
  if (type === "hmac") {
    return (signature === sign(input, key, method, type));
  }
  else if (type == "sign") {
    return createVerify(method)
      .update(input)
      .verify(key, base64urlUnescape(signature), 'base64');
  }
  else {
    throw new Error('Algorithm type not recognized');
  }
}