const keycloakConfig = {
  url: 'https://user.extrabot.ru/auth',
  realm: 'user_crm',
  clientId: 'open_client',
};

async function generateCodeChallenge(codeVerifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const hash = await crypto.subtle.digest('SHA-256', data);
  const base64Url = btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  return base64Url;
}

function getClientId() {
  return keycloakConfig.clientId;
}

function getState() {
  const state = Math.random().toString(36).substring(7);
  sessionStorage.setItem('state', state);
  return state;
}

async function login() {
  console.log('Hellow');
  const redirectUri = window.location.href;
  console.log(redirectUri);
  const state = getState();
  const codeVerifier = Math.random().toString(36).substring(7);
  const codeChallenge = await generateCodeChallenge(codeVerifier);
  const codeChallengeMethod = 'S256';
  sessionStorage.setItem('codeVerifier', codeVerifier);
  const url = `${keycloakConfig.url}/realms/${keycloakConfig.realm}/protocol/openid-connect/auth?response_type=code&scope=openid&client_id=${keycloakConfig.clientId}&state=${state}&redirect_uri=${redirectUri}&code_challenge=${codeChallenge}&code_challenge_method=${codeChallengeMethod}`;
  window.location.href = url;
}

async function getAccessToken(code) {
  console.log(window.location.href);
  console.log('getAccessToken');
  const tokenEndpoint = `${keycloakConfig.url}/realms/${keycloakConfig.realm}/protocol/openid-connect/token`;
  console.log(sessionStorage.getItem('codeVerifier'));
  const codeVerifier = sessionStorage.getItem('codeVerifier');
  const data = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: keycloakConfig.clientId,
    code: code,
    redirect_uri: window.location.href,
    code_verifier: codeVerifier,
  });

  const response = await fetch(tokenEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Access-Control-Allow-Origin': 'no-cors',
    },

    body: data,
  });
  console.log(response);
  const tokenData = await response.json();

  const accessToken = tokenData.access_token;
  console.log(accessToken);
  return accessToken;
}

async function getUserInfo(accessToken) {
  console.log('accessToken');
  console.log(accessToken);
  const url =
    'https://auth.extrabot.ru/auth/realms/user_crm/protocol/openid-connect/userinfo';
  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });
  const data = await response.json();
  return data;
}

async function displayUserInfo() {
  const accessToken = await getAccessToken(sessionStorage.getItem('code'));
  const userInfo = await getUserInfo(accessToken);
  const userName = userInfo.name;
  const clientId = getClientId();
  const result = `User Name: ${userName}\nClient ID: ${clientId}\nAccess Token: ${accessToken}`;
  document.getElementById('result').innerText = result;
}

const urlParams = new URLSearchParams(window.location.search);
const code = urlParams.get('code');
const state = urlParams.get('state');

if (code && state === sessionStorage.getItem('state')) {
  sessionStorage.setItem('code', code);
  displayUserInfo();
} else {
  document.getElementById('login').addEventListener('click', () => {
    login();
  });
}
