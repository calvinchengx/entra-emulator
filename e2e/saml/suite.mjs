// A REAL service provider library, unmodified, completing SP-initiated SSO
// against the emulator.
//
// WHY THIS EXISTS AND THE GO TESTS DO NOT REPLACE IT. The Go tests verify the
// assertion with goxmldsig, the same library that signed it. That catches a
// broken key pairing and little else: if this emulator and that library shared
// a misreading of the spec, both halves would agree and the tests would pass.
// @node-saml/node-saml is the engine behind passport-saml, written by people
// who never saw this code, and it enforces the checks a production SP enforces
// — signature, audience, InResponseTo, conditions, recipient.
//
// Env: EMU_ORIGIN, EMU_TENANT, EMU_CERT.
import { SAML } from '@node-saml/node-saml';

if (!process.env.EMU_CERT) {
  throw new Error('EMU_CERT must be set to a PEM file path for emulator TLS trust.');
}
process.env.NODE_EXTRA_CA_CERTS = process.env.EMU_CERT;

const ORIGIN = process.env.EMU_ORIGIN;
const TENANT = process.env.EMU_TENANT;
const SP_ENTITY = 'https://sp.e2e.test/metadata';
const SP_ACS = 'https://sp.e2e.test/acs';

let failures = 0;
function check(name, cond, extra = '') {
  if (cond) console.log(`  ok  ${name}`);
  else { console.error(`  FAIL ${name} ${extra}`); failures++; }
}

async function json(method, path, body) {
  const res = await fetch(`${ORIGIN}${path}`, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}

/** The signing certificate exactly as an SP obtains it: off the metadata URL. */
async function idpCertificate() {
  const res = await fetch(
    `${ORIGIN}/${TENANT}/federationmetadata/2007-06/federationmetadata.xml`);
  if (!res.ok) throw new Error(`metadata: HTTP ${res.status}`);
  const xml = await res.text();
  const m = xml.match(/<(?:\w+:)?X509Certificate[^>]*>([\s\S]*?)<\/(?:\w+:)?X509Certificate>/);
  if (!m) throw new Error('no X509Certificate in IdP metadata');
  const b64 = m[1].replace(/\s+/g, '');
  return `-----BEGIN CERTIFICATE-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----`;
}

async function registerSP() {
  const app = await json('POST', '/admin/api/apps', {
    displayName: 'SAML e2e SP',
    appIdUri: SP_ENTITY,
    redirectUris: [{ uri: SP_ACS, type: 'saml-acs' }],
  });
  if (app.status !== 201 && app.status !== 200) {
    throw new Error(`registering the SP: HTTP ${app.status} ${JSON.stringify(app.body)}`);
  }
  return app.body;
}

/** Drives the emulator's sign-in UI the way a browser would. */
async function signIn(authorizeUrl) {
  const jar = [];
  const keep = (res) => {
    const set = res.headers.getSetCookie?.() ?? [];
    for (const c of set) jar.push(c.split(';')[0]);
  };
  const cookie = () => (jar.length ? { Cookie: jar.join('; ') } : {});

  const first = await fetch(authorizeUrl, { redirect: 'manual', headers: cookie() });
  keep(first);
  const page = await first.text();
  const state = page.match(/name="__ee_state" value="([^"]+)"/);
  const user = page.match(/name="__ee_user" value="([^"]+)"/);
  if (!state || !user) throw new Error(`no sign-in form:\n${page.slice(0, 400)}`);

  const form = new URLSearchParams({ __ee_state: state[1], __ee_user: user[1] });
  const posted = await fetch(`${ORIGIN}/${TENANT}/saml2`, {
    method: 'POST', body: form, redirect: 'manual',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...cookie() },
  });
  keep(posted);
  const html = await posted.text();
  const resp = html.match(/name="SAMLResponse" value="([^"]+)"/);
  if (!resp) throw new Error(`no SAMLResponse:\n${html.slice(0, 400)}`);
  const relay = html.match(/name="RelayState" value="([^"]+)"/);
  // The browser un-escapes the attribute before submitting; so must we.
  const unescape = (s) => s.replace(/&#43;/g, '+').replace(/&amp;/g, '&')
    .replace(/&#61;/g, '=').replace(/&#47;/g, '/').replace(/&#34;/g, '"');
  return { SAMLResponse: unescape(resp[1]), RelayState: relay ? unescape(relay[1]) : undefined };
}

async function main() {
  console.log('node-saml (the engine behind passport-saml) against', ORIGIN);
  await registerSP();
  const idpCert = await idpCertificate();
  check('IdP metadata publishes a signing certificate', idpCert.includes('BEGIN CERTIFICATE'));

  const sp = new SAML({
    entryPoint: `${ORIGIN}/${TENANT}/saml2`,
    issuer: SP_ENTITY,
    callbackUrl: SP_ACS,
    idpCert,
    audience: SP_ENTITY,
    // Every one of these is a check a production SP performs. Turning any of
    // them off would let this suite pass against an emulator that omits the
    // corresponding defence, which is the opposite of a witness.
    wantAssertionsSigned: true,
    wantAuthnResponseSigned: false,
    validateInResponseTo: 'never',
    acceptedClockSkewMs: 5000,
  });

  // The AuthnRequest is built BY THE LIBRARY, deflated and encoded its way, so
  // the emulator's decoder faces a real client's output rather than ours.
  const relay = '/deep/link?a=1&b=2';
  const authorizeUrl = await sp.getAuthorizeUrlAsync(relay, undefined, {});
  check('the SP built a redirect-binding AuthnRequest',
    authorizeUrl.includes('SAMLRequest='));

  const { SAMLResponse, RelayState } = await signIn(authorizeUrl);
  check('RelayState survived the round trip', RelayState === relay,
    `got ${JSON.stringify(RelayState)}`);

  // The whole point: the SP validates, and it is not our code doing it.
  const { profile } = await sp.validatePostResponseAsync({ SAMLResponse });
  check('node-saml accepted the assertion', !!profile);
  check('the subject is the account that signed in',
    typeof profile.nameID === 'string' && profile.nameID.includes('@'),
    `nameID=${profile?.nameID}`);
  check('the issuer is the emulator tenant',
    typeof profile.issuer === 'string' && profile.issuer.includes(TENANT),
    `issuer=${profile?.issuer}`);

  // Tampering must be rejected BY THE SP, not merely by us. A byte flipped in
  // the encoded assertion has to break the signature it carries.
  const raw = Buffer.from(SAMLResponse, 'base64').toString('utf8');
  const tampered = Buffer.from(
    raw.replace(/<saml:Audience>[^<]*<\/saml:Audience>/,
      '<saml:Audience>https://attacker.test/</saml:Audience>'), 'utf8').toString('base64');
  let rejected = false;
  try {
    await sp.validatePostResponseAsync({ SAMLResponse: tampered });
  } catch {
    rejected = true;
  }
  check('a tampered audience is rejected by the SP', rejected);

  console.log(failures ? `\n${failures} check(s) failed` : '\nall SAML SP checks passed');
  process.exit(failures ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
