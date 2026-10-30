const allowedCategories = new Set(["全体", "男踊り", "女踊り", "絡み"]);

export async function onRequest(context) {
  const { request, env } = context;
  if (!env.DB) return Response.json({ error: "共有データベースが設定されていません。" }, { status: 503 });
  const role = context.data?.role || "member";

  if (request.method === "GET") {
    const { results } = await env.DB.prepare(
      "SELECT id, name, category, min, sec FROM compositions ORDER BY created_at ASC, name COLLATE NOCASE ASC"
    ).all();
    return Response.json({ compositions: results || [], role }, {
      headers: { "Cache-Control": "no-store" }
    });
  }

  if (role !== "admin") return Response.json({ error: "管理者のみ操作できます。" }, { status: 403 });

  if (request.method === "POST") {
    let body;
    try { body = await request.json(); } catch {
      return Response.json({ error: "送信内容を読み取れません。" }, { status: 400 });
    }
    const id = typeof body.id === "string" && /^[a-zA-Z0-9_-]{1,100}$/.test(body.id)
      ? body.id : crypto.randomUUID();
    const name = typeof body.name === "string" ? body.name.trim() : "";
    const category = body.category;
    const min = Number(body.min), sec = Number(body.sec);
    if (!name || name.length > 100 || !allowedCategories.has(category) ||
        !Number.isInteger(min) || min < 0 || min > 1440 ||
        !Number.isInteger(sec) || sec < 0 || sec > 59) {
      return Response.json({ error: "構成名・カテゴリー・時間を確認してください。" }, { status: 400 });
    }
    await env.DB.prepare(
      `INSERT INTO compositions (id, name, category, min, sec, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
       ON CONFLICT(id) DO UPDATE SET name=excluded.name, category=excluded.category,
       min=excluded.min, sec=excluded.sec, updated_at=CURRENT_TIMESTAMP`
    ).bind(id, name, category, min, sec).run();
    return Response.json({ ok: true, composition: { id, name, category, min, sec } });
  }

  if (request.method === "DELETE") {
    const id = new URL(request.url).searchParams.get("id") || "";
    if (!/^[a-zA-Z0-9_-]{1,100}$/.test(id)) return Response.json({ error: "IDが正しくありません。" }, { status: 400 });
    await env.DB.prepare("DELETE FROM compositions WHERE id = ?").bind(id).run();
    return Response.json({ ok: true });
  }

  return new Response("Method Not Allowed", { status: 405, headers: { Allow: "GET, POST, DELETE" } });
}
