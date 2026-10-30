
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

async function sign(data, password) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(data)
  );

  return base64url(signature);
}

async function validSession(request, env) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/(?:^|;\s*)planner_session=([^;]+)/);
  if (!match) return null;

  try {
    const parts = match[1].split(".");
    const expiry = Number(parts[0]);

    if (!Number.isFinite(expiry) || expiry < Date.now()) return null;

    // 新形式：有効期限・権限・署名
    if (parts.length === 3) {
      const role = parts[1];
      if (role !== "admin" && role !== "member") return null;

      const password = role === "admin"
        ? env.ADMIN_PASSWORD
        : env.SITE_PASSWORD;

      if (!password) return null;

      const expected = await sign(`${expiry}.${role}`, password);
      return parts[2] === expected ? role : null;
    }

    // 旧形式のログインCookieは一般ユーザーとして扱う
    if (parts.length === 2 && env.SITE_PASSWORD) {
      const expected = await sign(String(expiry), env.SITE_PASSWORD);
      return parts[1] === expected ? "member" : null;
    }

    return null;
  } catch {
    return null;
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
<p>パスワードを入力してください。</p>
${error ? "<p>パスワードが違います。</p>" : ""}
<form method="POST" action="/__login">
<input type="password" name="password" placeholder="パスワード" required>
<button type="submit">ログイン</button>
</form>
</main></body></html>`, {
    status: error ? 401 : 200,
    headers: {
      "Content-Type": "text/html; charset=UTF-8",
      "Cache-Control": "no-store"
    }
  });
}

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);

  if (!env.SITE_PASSWORD) {
    return new Response("Password configuration missing.", { status: 500 });
  }

// ログアウト
if (url.pathname === "/__logout") {
  const response = loginPage();

  response.headers.append(
    "Set-Cookie",
    "planner_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
  );

  response.headers.set("Cache-Control", "no-store");

  return response;
}

  // ログイン処理
  if (url.pathname === "/__login" && request.method === "POST") {
    const form = await request.formData();
    const entered = form.get("password");

    let role = null;

    if (typeof entered === "string") {
      if (env.ADMIN_PASSWORD && entered === env.ADMIN_PASSWORD) {
        role = "admin";
      } else if (entered === env.SITE_PASSWORD) {
        role = "member";
      }
    }

    if (!role) {
      return Response.redirect(url.origin + "/__login?error=1", 303);
    }

    const expiry = Date.now() + 7 * 24 * 60 * 60 * 1000;
    const password = role === "admin"
      ? env.ADMIN_PASSWORD
      : env.SITE_PASSWORD;

    const signature = await sign(`${expiry}.${role}`, password);

    return new Response(null, {
      status: 303,
      headers: {
        "Location": "/",
        "Set-Cookie": `planner_session=${expiry}.${role}.${signature}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`,
        "Cache-Control": "no-store"
      }
    });
  }

  if (url.pathname === "/__login") {
    return loginPage(url.searchParams.has("error"));
  }

  // ログイン済みか確認
  const role = await validSession(request, env);

  if (role) {
    context.data.role = role;
    return next();
  }

  return loginPage();
}
