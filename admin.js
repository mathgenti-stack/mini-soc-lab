// Painel do admin (estudar.html#admin): quem está testando, quanto avançou e o feedback enviado.
// Os dados vêm de conta.js (admin_overview e a tabela feedback): o servidor só entrega para o admin.
// Usa o que a página do curso já tem: TOP (tópicos e checklists), LAB (desafios por tópico), esc().
import { adminData, markFeedback, deleteFeedback, isAdmin } from "./conta.js";

const CSS = `
#adm{position:fixed;inset:0;z-index:1500;overflow:auto;background:var(--bg);color:var(--tx);font:15px/1.5 var(--sans)}
#adm .w{max-width:1100px;margin:0 auto;padding:24px 24px 64px}
#adm .top{display:flex;gap:12px;align-items:center;flex-wrap:wrap}
#adm h1{font-size:24px;margin:0;flex:1}
#adm h2{font-size:18px;margin:28px 0 10px}
#adm .ab{min-height:40px;padding:8px 14px;border-radius:10px;border:1px solid var(--bd);background:var(--sf);color:var(--tx);font:600 14px var(--sans);cursor:pointer}
#adm .ab.p{background:var(--ac);color:var(--onac);border-color:var(--ac)}
#adm .ab.s{min-height:30px;padding:4px 10px;font-size:13px}
#adm .kp{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-top:16px}
#adm .kp div{background:var(--sf);border:1px solid var(--bd);border-radius:14px;padding:14px 16px}
#adm .kp b{display:block;font-size:26px}
#adm .kp span{color:var(--mu);font-size:13px}
#adm table{width:100%;border-collapse:collapse;background:var(--sf);border:1px solid var(--bd);border-radius:14px;overflow:hidden}
#adm th,#adm td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--bd);vertical-align:top}
#adm th{font-size:12px;color:var(--mu);font-weight:600;text-transform:uppercase;letter-spacing:.03em}
#adm tr.pp{cursor:pointer}
#adm tr.pp:hover td{background:var(--acs)}
#adm .mu{color:var(--mu);font-size:13px}
#adm .num{font-variant-numeric:tabular-nums;white-space:nowrap}
#adm .bar{display:block;height:6px;border-radius:3px;background:var(--bd);margin-top:5px;min-width:80px}
#adm .bar i{display:block;height:100%;border-radius:3px;background:var(--ac)}
#adm .det td{background:var(--bg)}
#adm .tg{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:8px 20px;margin:6px 0 12px}
#adm .chips span{display:inline-block;font:12px var(--mono);background:var(--acs);border-radius:6px;padding:2px 7px;margin:2px}
#adm .fb{background:var(--sf);border:1px solid var(--bd);border-radius:14px;padding:12px 16px;margin-bottom:10px}
#adm .fb.done{opacity:.55}
#adm .fb p{margin:6px 0;white-space:pre-wrap;word-break:break-word}
#adm .fb .row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
#adm .fb .row .mu{flex:1}
#adm .err{color:var(--bad)}
`;

const DAY = 86400000;
const when = (iso) => {
  if (!iso) return "—";
  const d = new Date(iso), ago = Date.now() - d.getTime();
  const rel = ago < 3600000 ? `há ${Math.max(1, Math.round(ago / 60000))} min` : ago < DAY ? `há ${Math.round(ago / 3600000)} h`
    : ago < 30 * DAY ? `há ${Math.round(ago / DAY)} dia${Math.round(ago / DAY) > 1 ? "s" : ""}` : "";
  return `${d.toLocaleDateString("pt-BR")} ${d.toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" })}${rel ? ` <span class="mu">(${rel})</span>` : ""}`;
};
const pct = (a, b) => (b ? Math.round((100 * a) / b) : 0);
const bar = (p) => `<span class="bar"><i style="width:${p}%"></i></span>`;

// Resumo de uma pessoa a partir do que a página do curso e o lab salvam.
function summary(row) {
  const c = row.course || {}, tdone = c.tdone || {};
  const topics = TOP.map((t) => {
    const d = t.chk.filter((_, j) => tdone[t.id + "-" + j]).length;
    return { t, d, n: t.chk.length };
  });
  const items = topics.reduce((a, x) => [a[0] + x.d, a[1] + x.n], [0, 0]);
  const st = Object.values(c.st || {}).reduce((a, v) => [a[0] + (v[0] || 0), a[1] + (v[1] || 0)], [0, 0]);
  const days = new Set([...Object.keys(c.days || {}), ...Object.keys(c.hoje || {}).filter((k) => {
    const h = c.hoje[k]; return h && (Object.values(h.t || {}).some(Boolean) || (h.n || "").trim());
  })]);
  const solved = {};
  let training = 0;
  for (const [name, text] of Object.entries(row.lab || {})) {
    const m = /^terminal_([\w-]+)\.json$/.exec(name);
    if (!m) { training++; continue; }
    try { solved[m[1]] = JSON.parse(text).solved || []; } catch (e) {}
  }
  const nSolved = Object.values(solved).reduce((a, l) => a + l.length, 0);
  const lastDay = [...days].sort().pop();
  return { topics, items, quiz: st, days: days.size, lastDay, solved, nSolved, training };
}

function labTotal() {
  const ids = new Set();
  Object.values(LAB || {}).forEach((l) => l.forEach((x) => ids.add(x[0])));
  return ids.size;
}

function personHTML(row, s, i, total) {
  const who = row.name ? `<b>${esc(row.name)}</b><div class="mu">${esc(row.email)}</div>` : `<b>${esc(row.email)}</b>`;
  const last = [row.last_sign_in_at, row.updated_at].filter(Boolean).sort().pop();
  const doing = s.topics.filter((x) => x.d > 0 && x.d < x.n).map((x) => x.t.n);
  return `<tr class="pp" data-i="${i}"><td>${who}</td><td class="num">${when(last)}</td>
    <td class="num">${pct(s.items[0], s.items[1])}%${bar(pct(s.items[0], s.items[1]))}<span class="mu">${s.items[0]} de ${s.items[1]} itens</span></td>
    <td class="num">${s.quiz[1] ? `${s.quiz[1]} resp.<div class="mu">${pct(s.quiz[0], s.quiz[1])}% de acerto</div>` : '<span class="mu">—</span>'}</td>
    <td class="num">${s.nSolved} de ${total}${bar(pct(s.nSolved, total))}${s.training ? `<span class="mu">${s.training} alertas no treino</span>` : ""}</td>
    <td class="num">${s.days}${s.lastDay ? `<div class="mu">último: ${new Date(s.lastDay + "T12:00").toLocaleDateString("pt-BR")}</div>` : ""}</td>
    <td>${doing.length ? esc(doing.slice(0, 3).join(", ")) + (doing.length > 3 ? ` <span class="mu">+${doing.length - 3}</span>` : "") : '<span class="mu">—</span>'}</td></tr>
    <tr class="det" id="adm-d${i}" hidden><td colspan="7">${detailHTML(row, s)}</td></tr>`;
}

function detailHTML(row, s) {
  const started = s.topics.filter((x) => x.d > 0);
  const envs = Object.entries(s.solved).filter(([, l]) => l.length);
  return `<div class="mu">Conta criada em ${when(row.created_at)} · progresso salvo pela última vez em ${when(row.updated_at)}</div>
    <h3 style="font-size:15px;margin:12px 0 4px">Tópicos (checklist)</h3>
    ${started.length ? `<div class="tg">${started.map((x) => `<div>${esc(x.t.n)} <span class="mu">${x.d}/${x.n}</span>${bar(pct(x.d, x.n))}</div>`).join("")}</div>` : '<p class="mu">Nenhum item marcado ainda.</p>'}
    <h3 style="font-size:15px;margin:12px 0 4px">Desafios resolvidos no lab</h3>
    ${envs.length ? envs.map(([e, l]) => `<div class="chips"><span style="background:none;padding-left:0"><b>${esc(e)}</b></span>${l.map((id) => `<span>${esc(id)}</span>`).join("")}</div>`).join("") : '<p class="mu">Nenhum ainda.</p>'}`;
}

function feedbackHTML(fb, people) {
  const by = Object.fromEntries(people.map((p) => [p.user_id, p]));
  if (!fb.length) return '<p class="mu">Nenhum feedback ainda.</p>';
  return fb.map((f) => {
    const p = by[f.user_id];
    const who = p ? esc(p.name || p.email) : "visitante sem login";
    return `<div class="fb${f.resolved ? " done" : ""}" data-id="${f.id}">
      <div class="row"><span class="mu">${when(f.created_at)} · <b>${who}</b> · ${f.page === "lab" ? "🧪 lab" : "📖 curso"}${f.context ? " · " + esc(f.context) : ""}</span>
      <button class="ab s" data-act="mark">${f.resolved ? "Reabrir" : "✓ Resolvido"}</button><button class="ab s" data-act="del">Apagar</button></div>
      <p>${esc(f.message)}</p></div>`;
  }).join("");
}

let root = null;
async function render() {
  const w = root.querySelector(".w .body");
  w.innerHTML = '<p class="mu">Carregando…</p>';
  try {
    if (!Object.keys(LAB || {}).length && typeof loadLab === "function") await loadLab();
    const { people, feedback } = await adminData();
    const total = labTotal();
    const sums = people.map(summary);
    const week = people.filter((p) => [p.last_sign_in_at, p.updated_at].some((x) => x && Date.now() - new Date(x) < 7 * DAY)).length;
    const open = feedback.filter((f) => !f.resolved).length;
    w.innerHTML = `<div class="kp"><div><b>${people.length}</b><span>pessoas com conta</span></div>
      <div><b>${week}</b><span>ativas nos últimos 7 dias</span></div>
      <div><b>${sums.reduce((a, s) => a + s.nSolved, 0)}</b><span>desafios resolvidos (todos)</span></div>
      <div><b>${open}</b><span>feedbacks em aberto</span></div></div>
      <h2>Pessoas <span class="mu" style="font-weight:400">· clique numa linha para ver os detalhes</span></h2>
      ${people.length ? `<div style="overflow-x:auto"><table><thead><tr><th>Pessoa</th><th>Último acesso</th><th>Curso</th><th>Quiz</th><th>Lab</th><th>Dias de estudo</th><th>Em andamento</th></tr></thead>
      <tbody>${people.map((p, i) => personHTML(p, sums[i], i, total)).join("")}</tbody></table></div>` : '<p class="mu">Ninguém entrou ainda.</p>'}
      <h2>Feedback</h2><div id="adm-fb">${feedbackHTML(feedback, people)}</div>`;
    w.querySelectorAll("tr.pp").forEach((tr) => tr.onclick = () => {
      const d = w.querySelector("#adm-d" + tr.dataset.i);
      d.hidden = !d.hidden;
    });
    w.querySelectorAll(".fb button").forEach((b) => b.onclick = async () => {
      const box = b.closest(".fb"), id = +box.dataset.id, f = feedback.find((x) => x.id === id);
      try {
        if (b.dataset.act === "del") {
          if (!confirm("Apagar este feedback?")) return;
          await deleteFeedback(id);
        } else await markFeedback(id, !f.resolved);
        render();
      } catch (e) { alert("Não deu certo: " + (e.message || e)); }
    });
  } catch (e) {
    w.innerHTML = `<p class="err">Não foi possível carregar: ${esc(e.message || e)}</p><p class="mu">Este painel é só para o admin. Entre com a conta de admin.</p>`;
  }
}

export async function openAdmin() {
  if (!(await isAdmin())) { alert("Este painel é só para o admin. Entre com a conta de admin."); return; }
  if (!document.getElementById("adm-css")) {
    const s = document.createElement("style");
    s.id = "adm-css";
    s.textContent = CSS;
    document.head.appendChild(s);
  }
  if (!root) {
    root = document.createElement("div");
    root.id = "adm";
    root.setAttribute("role", "dialog");
    root.setAttribute("aria-label", "Painel do admin");
    root.innerHTML = `<div class="w"><div class="top"><h1>📊 Painel do admin</h1>
      <button class="ab" id="adm-r">Atualizar</button><button class="ab p" id="adm-x">Fechar</button></div><div class="body"></div></div>`;
    root.querySelector("#adm-x").onclick = () => { root.hidden = true; document.body.style.overflow = ""; };
    root.querySelector("#adm-r").onclick = render;
    document.body.appendChild(root);
  }
  root.hidden = false;
  document.body.style.overflow = "hidden";
  await render();
}
