
function base64url(bytes) {
  let binary = "";
  for (const byte of new Uint8Array(bytes)) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function sign(expiry, password) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );

  const data = new TextEncoder().encode(String(expiry));
  const signature = await crypto.subtle.sign("HMAC", key, data);
  return base64url(signature);
}

async function validSession(request, password) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/(?:^|;\s*)planner_session=([^;]+)/);
  if (!match) return false;

  try {
    const [expiryText, signature] = match[1].split(".");
    const expiry = Number(expiryText);

    if (!Number.isFinite(expiry) || expiry < Date.now()) return false;

    const expected = await sign(expiry, password);
    return signature === expected;
  } catch {
    return false;
  }
}

function loginPage(error = false) {
  return new Response(`<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ログイン</title>
<style>
body{font-family:sans-serif;background:#111827;color:white;
display:grid;place-items:center;min-height:100vh;margin:0}
main{background:#1f2937;padding:32px;border-radius:16px;
width:min(85%,340px);text-align:center}
input,button{box-sizing:border-box;width:100%;padding:14px;
margin-top:14px;border-radius:8px;font-size:16px}
button{background:#c5a45e;color:#111;border:0;font-weight:bold}
p{color:#fca5a5}
</style>
</head>
<body><main>
<h2>阿波おどり 演舞プランナー</h2>
<p>共通パスワードを入力してください。</p>
${error ? "<p>パスワードが違います。</p>" : ""}
<form method="POST" action="/__login">
<input type="password" name="password" placeholder="パスワード" required>
<button type="submit">ログイン</button>
</form>
</main></body></html>`, {
    status: error ? 401 : 200,
    headers: { "Content-Type": "text/html; charset=UTF-8", "Cache-Control": "no-store" }
  });
}

export async function onRequest(context) {
  const { request, env, next } = context;
  const password = env.SITE_PASSWORD;

  if (!password) {
    return new Response("Password configuration missing.", { status: 500 });
  }

  const url = new URL(request.url);

  if (url.pathname === "/__login" && request.method === "POST") {
    const form = await request.formData();
    const entered = form.get("password");

    if (typeof entered !== "string" || entered !== password) {
      return Response.redirect(url.origin + "/__login?error=1", 303);
    }

    const expiry = Date.now() + 7 * 24 * 60 * 60 * 1000;
    const signature = await sign(expiry, password);

    return new Response(null, {
      status: 303,
      headers: {
        "Location": "/",
        "Set-Cookie": `planner_session=${expiry}.${signature}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`,
        "Cache-Control": "no-store"
      }
    });
  }

  if (url.pathname === "/__login") {
    return loginPage(url.searchParams.has("error"));
  }

  if (await validSession(request, password)) {
    return next();
  }

  return loginPage();
}
