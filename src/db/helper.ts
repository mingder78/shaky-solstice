export async function getUserbyName(username: string) {
    const response = await fetch(`/webauthn/getuserbyname/${username}`);
    if (!response.ok) {
      console.log(`Error: ${response.status}`); // Handle HTTP errors like 404, 500, etc.
      return;
    }
    const data = await response.json();
    console.log(data);
  }
  