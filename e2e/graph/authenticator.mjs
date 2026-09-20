// A software WebAuthn authenticator: ES256 credentials, "none" attestation, no
// dependencies beyond node:crypto. It exists so the Graph suite can register a
// passkey for a user, which Graph's own fido2Methods API cannot do (Graph only
// lists and deletes them; registration is the WebAuthn ceremony).
//
// Deliberately written from the WebAuthn and CTAP2 specs rather than taken from
// a library, and deliberately sharing nothing with the emulator's go-webauthn:
// the emulator then verifies bytes it did not help produce.
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';

const sha256 = (b) => createHash('sha256').update(b).digest();
const b64u = (b) => Buffer.from(b).toString('base64url');
const fromB64u = (s) => Buffer.from(s, 'base64url');

/** CBOR head for a major type and length (RFC 8949 3), lengths under 65536. */
function head(major, n) {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 256) return Buffer.from([(major << 5) | 24, n]);
  return Buffer.from([(major << 5) | 25, n >> 8, n & 0xff]);
}
const bytes = (b) => Buffer.concat([head(2, b.length), b]);
const text = (s) => Buffer.concat([head(3, Buffer.byteLength(s)), Buffer.from(s)]);
const int = (n) => (n >= 0 ? head(0, n) : head(1, -1 - n));

export class VirtualAuthenticator {
  constructor() {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    this.privateKey = privateKey;
    this.jwk = publicKey.export({ format: 'jwk' });
    this.credentialId = randomBytes(32);
    this.signCount = 0;
  }

  get id() { return b64u(this.credentialId); }

  /** The public key as a COSE_Key (RFC 9052): EC2, ES256, P-256. Map keys are in
   *  CTAP2 canonical order, which is what a real authenticator emits. */
  #coseKey() {
    return Buffer.concat([
      head(5, 5),
      int(1), int(2), // kty: EC2
      int(3), int(-7), // alg: ES256
      int(-1), int(1), // crv: P-256
      int(-2), bytes(fromB64u(this.jwk.x)),
      int(-3), bytes(fromB64u(this.jwk.y)),
    ]);
  }

  #authData(rpId, flags, withCredential) {
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(this.signCount);
    const parts = [sha256(rpId), Buffer.from([flags]), counter];
    if (withCredential) {
      const idLen = Buffer.alloc(2);
      idLen.writeUInt16BE(this.credentialId.length);
      parts.push(Buffer.alloc(16), idLen, this.credentialId, this.#coseKey());
    }
    return Buffer.concat(parts);
  }

  /** Answer a navigator.credentials.create() request. `options` is the
   *  `publicKey` member of what the relying party sent. */
  create(options, origin) {
    const clientDataJSON = Buffer.from(JSON.stringify({
      type: 'webauthn.create', challenge: options.challenge, origin, crossOrigin: false,
    }));
    // flags: UP (0x01) | UV (0x04) | AT (0x40)
    const authData = this.#authData(options.rp.id, 0x45, true);
    const attestationObject = Buffer.concat([
      head(5, 3),
      text('fmt'), text('none'),
      text('attStmt'), head(5, 0),
      text('authData'), bytes(authData),
    ]);
    return {
      id: this.id, rawId: this.id, type: 'public-key',
      response: { clientDataJSON: b64u(clientDataJSON), attestationObject: b64u(attestationObject) },
    };
  }

  /** Answer a navigator.credentials.get() request. */
  get(options, origin, userHandle) {
    this.signCount += 1;
    const clientDataJSON = Buffer.from(JSON.stringify({
      type: 'webauthn.get', challenge: options.challenge, origin, crossOrigin: false,
    }));
    const authData = this.#authData(options.rpId, 0x05, false); // UP | UV
    // ES256 over authData || SHA-256(clientDataJSON); node emits the DER form
    // WebAuthn wants.
    const signature = sign('sha256', Buffer.concat([authData, sha256(clientDataJSON)]), this.privateKey);
    return {
      id: this.id, rawId: this.id, type: 'public-key',
      response: {
        clientDataJSON: b64u(clientDataJSON), authenticatorData: b64u(authData),
        signature: b64u(signature), userHandle,
      },
    };
  }
}
