import { db } from "./db";
import { decodeBase64Url, encodeBase64Url } from "./encode";
import { verifyAssertion } from "./passkey";
import { getUserbyName } from "../db/helper";
// Helper to convert ArrayBuffer to base64
function arrayBufferToBase64(buffer: ArrayBuffer): string {
	return btoa(String.fromCharCode(...new Uint8Array(buffer)));
  }

type User = {
  userId: string;
  username: string;
};

// Fetch and display users
async function getPublicKeyOptions() {
  const apiUrl = "/api/register/start";
  const res = await fetch(apiUrl);
  const public_key = await res.json();
  console.log(public_key);
  return public_key;
}

export async function signUp(username: string): Promise<User> {
	console.log(`signUp: ${username}`);
  // should be handled in server - start (done in the server)
  // check if username already exists
  const publicKeyOptions = await getPublicKeyOptions();
  // should be handled in server - end

  const challengeBase64 = publicKeyOptions.challenge;
    const challengeArrayBuffer = Uint8Array.from(atob(challengeBase64), c => c.charCodeAt(0));
    publicKeyOptions.challenge = challengeArrayBuffer;
  
  console.log(`challenge: ${publicKeyOptions.challenge}`);	
console.log(`publicKeyOptions: ${publicKeyOptions}`);

const challengeBase64userid = publicKeyOptions.user.id;
const challengeArrayBufferuserid= Uint8Array.from(atob(challengeBase64userid), c => c.charCodeAt(0));
publicKeyOptions.user.id = challengeArrayBufferuserid;

console.log(`user.id: ${publicKeyOptions.user.id}`);

  const publicKeyCredential = await navigator.credentials.create(
    // publicKey = Web Authentication API
    { publicKey: publicKeyOptions }
  );

  console.log(`publicKeyCredential: ${publicKeyCredential}`);
  if (!(publicKeyCredential instanceof PublicKeyCredential)) {
    throw new TypeError();
  }
  if (
    !(publicKeyCredential.response instanceof AuthenticatorAttestationResponse)
  ) {
    throw new TypeError("Unexpected attestation response");
  }

  // should be handled in server from here
  const userId = generateId(8);
  const publicKey = publicKeyCredential.response.getPublicKey();
  console.log(`getPublicKey: ${publicKey}`);
  if (!publicKey) {
    throw new Error("Could not retrieve public key");
  }
  /*
  db.insert({
    id: userId,
    credential_id: publicKeyCredential.id, // base64url encoded
    username,
    public_key: encodeBase64Url(publicKey),
  });
*/
   // Send response back to server
   const credentialData = {
    id: publicKeyCredential.id,
    rawId: arrayBufferToBase64(publicKeyCredential.rawId),
    response: {
      attestationObject: arrayBufferToBase64(publicKeyCredential.response.attestationObject),
      clientDataJSON: arrayBufferToBase64(publicKeyCredential.response.clientDataJSON),
    },
    type: publicKeyCredential.type,
  };

  console.log(`credentialData JSON: ${JSON.stringify(credentialData)}`);

  await fetch('/api/register/complete', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(credentialData),
  });

  console.log('Registration complete!');

  return { userId, username };
}

export async function signIn(): Promise<User> {
  // should be generated in server
  // recommend minimum 16 bytes
  const challenge = crypto.getRandomValues(new Uint8Array(32));

  const publicKeyCredential = await navigator.credentials.get({
    publicKey: {
      challenge,
    },
  });
  if (!(publicKeyCredential instanceof PublicKeyCredential)) {
    throw new TypeError();
  }

  // should be handled in server - start
  const databaseUser = db.getByCredentialId(publicKeyCredential.id);
  if (!databaseUser) {
    throw new Error("User does not exist");
  }

  await verifyAssertion(publicKeyCredential, {
    publicKey: decodeBase64Url(databaseUser.public_key),
    challenge,
  });
  // should be handled in server - end

  return {
    userId: databaseUser.id,
    username: databaseUser.username,
  };
}

// the most inefficient random id generator
// possible characters: 0-9, a-z
export function generateId(length: number) {
  let result = "";
  const alphabet = "0123456789abcdefghijklmnopqrstuvwxyz";
  while (result.length !== length) {
    const index = Math.floor(crypto.getRandomValues(new Uint8Array(1))[0] / 4);
    if (index >= alphabet.length) continue;
    result += alphabet[index];
  }
  return result;
}
