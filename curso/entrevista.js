/* ===== Simulação de entrevista (curso/entrevista.js, copiado para estudar.html por curso/montar.py) =====
   As perguntas técnicas vêm das seções "Como explicar numa entrevista" dos próprios tópicos (TOP[].st):
   cada <p><b>pergunta</b><br><i>resposta modelo</i></p> vira uma pergunta. ENT_RH (curso/montar.py) traz as
   perguntas de RH. Progresso em S.ent: {hist:[...], last:{id:nota}, lang}.
   Também aqui: a avaliação rápida (rateCard) e o convite para entrar na conta (nudgeCard). */
var ENTC = null;
let ENTQ = null, ENTSET = null, RATEP = {};

function entBank() {
  if (ENTQ) return ENTQ;
  ENTQ = [];
  const phase = {};
  let f = -1;
  MODS.forEach(m => { if (m.f) f++; m.ids.forEach(id => { if (phase[id] == null) phase[id] = f <= 0 ? "sd" : "soc" }) });
  TOP.forEach(t => {
    const d = document.createElement("div");
    d.innerHTML = t.st;
    const h3 = [...d.querySelectorAll("h3")].find(x => /entrevista/i.test(x.textContent));
    if (!h3) return;
    let k = 0;
    for (let e = h3.nextElementSibling; e && e.tagName != "H3"; e = e.nextElementSibling) {
      const b = e.querySelector && e.querySelector("b"), i = e.querySelector && e.querySelector("i");
      if (!b || !i) continue;
      ENTQ.push({ id: t.id + "-" + (++k), q: b.textContent.trim(), a: i.textContent.trim(), tp: t.id, tn: t.n, ic: t.ic, area: phase[t.id] || "soc" });
    }
  });
  ENT_RH.forEach(x => ENTQ.push(Object.assign({ area: "rh", ic: "🤝", tn: "RH" }, x)));
  return ENTQ;
}

/* palavras-chave da resposta modelo: siglas, números e palavras longas */
const ENT_STOP = new Set(("the and that this with from have they them their then than what when where which while into your about also just like only some such very will would could " +
  "should there these those been being does doing done each other more most much many over under after before because first second check look need want work works " +
  "working thing things something someone usually always often people person using used make sure know sometimes trying")
  .split(" "));
function entKeys(a) {
  const seen = {}, out = [];
  (a.match(/[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9]/g) || []).forEach(w => {
    const lw = w.toLowerCase(), strong = /\d/.test(w) || /^[A-Z]{2,}/.test(w);
    if (seen[lw] || ENT_STOP.has(lw)) return;
    if (!strong && lw.length < 6) return;
    seen[lw] = 1;
    out.push({ w, lw, strong });
  });
  out.sort((x, y) => (y.strong - x.strong) || (y.lw.length - x.lw.length));
  return out.slice(0, 8);
}
const entStem = lw => lw.length > 6 ? lw.slice(0, lw.length - 3) : lw;
function entCover(a, ans) {
  const t = " " + String(ans || "").toLowerCase() + " ";
  return entKeys(a).map(k => Object.assign({ hit: k.strong ? new RegExp("(^|[^a-z0-9])" + k.lw.replace(/[-]/g, "\\-") + "([^a-z0-9]|$)").test(t) : t.includes(entStem(k.lw)) }, k));
}
function entMark(a, cov) {
  let h = esc(a);
  cov.forEach(k => { h = h.replace(new RegExp("\\b(" + k.w.replace(/[-]/g, "\\-") + ")\\b"), `<mark class="${k.hit ? "hit" : "miss"}">$1</mark>`) });
  return h;
}

const ENT_ROLES = { sd: ["🎧", "Service Desk / Suporte N1", "Primeiro emprego em TI: atendimento, Windows, redes e contas."], soc: ["🛡️", "Analista de SOC N1", "Alertas, logs, SIEM, phishing e resposta a incidentes."], mix: ["🔀", "Misturado", "Um pouco de cada, como numa entrevista de verdade."] };
const ENT_RATE = [["😬", "Preciso treinar", 0], ["🙂", "Quase lá", 1], ["😃", "Mandei bem", 2]];

function entWhere() {
  if (!ENTC) return "";
  const q = ENTC.qs[Math.min(ENTC.i, ENTC.qs.length - 1)];
  return ENTC.i >= ENTC.qs.length ? "resultado" : "pergunta " + (ENTC.i + 1) + " · " + q.q.slice(0, 70);
}
function entStarted(id) { const t = TOP.find(x => x.id == id); return t ? tStatus(t) != "new" : false }

/* começa uma entrevista. o: {role, n, rh, only, topic, ids} */
function entStart(o) {
  S.ent = S.ent || { hist: [], last: {} };
  const B = entBank(), last = S.ent.last || {};
  let pool;
  if (o.ids) pool = B.filter(x => o.ids.includes(x.id));
  else if (o.topic) pool = B.filter(x => x.tp == o.topic);
  else {
    pool = B.filter(x => x.area != "rh" && (o.role == "mix" || x.area == o.role) && (!o.only || entStarted(x.tp)));
    if (!pool.length) pool = B.filter(x => x.area != "rh" && (o.role == "mix" || x.area == o.role));
    // primeiro o que nunca viu ou ainda não domina
    pool = shuf(pool).sort((a, b) => (last[a.id] == null ? -1 : last[a.id]) - (last[b.id] == null ? -1 : last[b.id]));
    pool = pool.slice(0, Math.max(1, o.n - (o.rh ? 1 : 0)));
    if (o.rh) { const rh = shuf(B.filter(x => x.area == "rh")).sort((a, b) => (last[a.id] == null ? -1 : last[a.id]) - (last[b.id] == null ? -1 : last[b.id])); pool.unshift(rh[0]) }
  }
  ENTC = { o, qs: pool, i: 0, ans: {}, rate: {}, cov: {}, secs: {}, ph: "q", t0: Date.now() };
  goTab(10); window.scrollTo(0, 0);
}

function entTimer() {
  clearInterval(entTimer.h);
  entTimer.h = setInterval(() => {
    const e = $("entclk");
    if (!e || !ENTC || ENTC.ph != "q") { clearInterval(entTimer.h); return }
    const s = Math.round((Date.now() - ENTC.t0) / 1000);
    e.textContent = "⏱ " + Math.floor(s / 60) + ":" + String(s % 60).padStart(2, "0");
    e.classList.toggle("long", s > 120);
  }, 1000);
}
function entSay(text) {
  try {
    const u = new SpeechSynthesisUtterance(text);
    u.lang = "en-US"; u.rate = .95;
    speechSynthesis.cancel(); speechSynthesis.speak(u);
  } catch (e) { toast("Este navegador não lê em voz alta.") }
}

function rEnt() {
  const el = $("v10");
  if (!ENTC) return entSetup(el);
  if (ENTC.i >= ENTC.qs.length) return entEnd(el);
  const c = ENTC, q = c.qs[c.i], n = c.qs.length, lang = (S.ent && S.ent.lang) || "en-US";
  let h = `<div class="enthd"><button class="btn" id="entx">✕ Sair</button><span class="mu">Pergunta ${c.i + 1} de ${n}</span>${c.ph == "q" ? `<span class="entclk" id="entclk">⏱ 0:00</span>` : ""}</div><span class="bar entbar"><i style="width:${100 * c.i / n}%"></i></span>`;
  h += `<div class="entq"><div class="eav">👩‍💼</div><div class="ebub"><span class="ek">Entrevistadora</span><p class="eqt">${esc(q.q)}</p>${q.pt ? `<p class="mu ept">${esc(q.pt)}</p>` : ""}<div class="row"><button class="btn sm" id="entsay">🔊 Ouvir a pergunta</button><span class="etag">${q.ic || ""} ${esc(q.tn)}</span></div></div></div>`;
  if (c.ph == "q") {
    h += `<div class="card entans"><div class="q">Sua resposta</div><p class="mu">Responda como se estivesse na entrevista: em voz alta (o botão escreve por você) ou digitando. Bom tamanho: de 30 segundos a 2 minutos.</p>`
      + `<div class="pills entlang"><button class="pill${lang == "en-US" ? " on" : ""}" data-lang="en-US">Em inglês</button><button class="pill${lang == "pt-BR" ? " on" : ""}" data-lang="pt-BR">Em português</button></div>`
      + `<textarea id="enta" placeholder="${lang == "en-US" ? "I would..." : "Eu faria..."}">${esc(c.ans[q.id] || "")}</textarea><p class="mu" id="entmsg"></p>`
      + `<div class="row"><button class="btn" id="entmic">🎤 Falar</button><button class="btn p" id="entok">Ver resposta →</button></div><div class="row"><button class="btn sm ghost" id="entskip">Não sei, pular</button></div></div>`;
    if (q.tip) h += `<div class="card enttip"><b>💡 Dica</b><p class="mu">${esc(q.tip)}</p></div>`;
  } else {
    const ans = c.ans[q.id] || "", cov = c.cov[q.id] || [], hit = cov.filter(k => k.hit).length, words = ans.trim() ? ans.trim().split(/\s+/).length : 0;
    h += ans.trim() ? `<div class="entq me"><div class="ebub"><span class="ek">Você</span><p>${esc(ans)}</p></div><div class="eav">🙋</div></div>` : `<p class="mu">Você pulou esta. Leia a resposta modelo com calma e tente dizer com as suas palavras.</p>`;
    h += `<div class="card entmod"><div class="q">✅ Resposta modelo</div><p class="ema">${entMark(q.a, cov)}</p>`
      + (cov.length ? `<div class="chips"><span class="chip">${hit} de ${cov.length} palavras-chave</span>${words ? `<span class="chip off">${words} palavras · ${c.secs[q.id] || 0}s</span>` : ""}</div>` : "")
      + `<p class="mu sm">${(S.ent && S.ent.lang) == "pt-BR" ? "Você respondeu em português: a comparação só acha siglas e números. Vale mais a sua autoavaliação." : "Verde: você falou. Laranja: faltou falar (ou falou de outro jeito)."}</p>`
      + (words && words < 15 ? `<p class="ewarn">Resposta curta. Na entrevista, diga o que você faria, por quê, e dê um exemplo.</p>` : "")
      + (words > 180 ? `<p class="ewarn">Resposta longa. Tente chegar ao ponto em até 2 minutos.</p>` : "")
      + (q.tp ? `<button class="btn sm ghost" id="entrev">📖 Rever o tópico ${esc(q.tn)}</button>` : "") + `</div>`;
    const r = c.rate[q.id];
    h += `<div class="card"><div class="q">Como você se saiu?</div><p class="mu">Seja sincero: as que você marcar como "Preciso treinar" voltam primeiro na próxima vez.</p><div class="erate">${ENT_RATE.map(([ic, t, v]) => `<button class="${r === v ? "on" : ""}" data-r="${v}"><span>${ic}</span>${t}</button>`).join("")}</div></div>`;
    if (r != null) h += `<div class="nextc"><button class="btn p" id="entnx">${c.i + 1 < n ? "Próxima pergunta →" : "Ver o resultado →"}</button></div>`;
  }
  el.innerHTML = h;
  $("entx").onclick = () => ask("Sair da entrevista? As respostas desta vez não ficam salvas.", () => { ENTC = null; rEnt() }, "Sair");
  $("entsay").onclick = () => entSay(q.q);
  if (c.ph == "q") {
    entTimer();
    const ta = $("enta");
    ta.oninput = () => { c.ans[q.id] = ta.value };
    el.querySelectorAll("[data-lang]").forEach(b => b.onclick = () => { S.ent.lang = b.dataset.lang; save(); rEnt() });
    $("entmic").onclick = () => dictate(ta, (S.ent && S.ent.lang) || "en-US", $("entmic"), $("entmsg"));
    const go = () => { const b = $("entmic"); if (b && b._r) b._r.stop(); c.ans[q.id] = ta.value; c.secs[q.id] = Math.round((Date.now() - c.t0) / 1000); c.cov[q.id] = ta.value.trim() ? entCover(q.a, ta.value) : []; c.ph = "r"; rEnt(); window.scrollTo(0, 0) };
    $("entok").onclick = () => { if (!ta.value.trim()) { $("entmsg").textContent = "Responda alguma coisa, mesmo curta. Ou toque em \"Não sei, pular\"."; return } go() };
    $("entskip").onclick = () => { ta.value = ""; go() };
  } else {
    el.querySelectorAll("[data-r]").forEach(b => b.onclick = () => { c.rate[q.id] = +b.dataset.r; rEnt() });
    if ($("entrev")) $("entrev").onclick = () => openTopic(TOP.find(t => t.id == q.tp), "Estudar");
    if ($("entnx")) $("entnx").onclick = () => { c.i++; c.ph = "q"; c.t0 = Date.now(); if (c.i >= n) entSave(); rEnt(); window.scrollTo(0, 0) };
  }
}

function entSave() {
  const c = ENTC, pts = c.qs.reduce((a, q) => a + (c.rate[q.id] || 0), 0), score = Math.round(100 * pts / (2 * c.qs.length));
  S.ent = S.ent || { hist: [], last: {} };
  S.ent.last = S.ent.last || {}; S.ent.hist = S.ent.hist || [];
  c.qs.forEach(q => S.ent.last[q.id] = c.rate[q.id] || 0);
  S.ent.hist.unshift({ d: new Date().toISOString().slice(0, 10), role: c.o.topic ? "topic:" + c.o.topic : c.o.role || "mix", n: c.qs.length, s: score });
  S.ent.hist = S.ent.hist.slice(0, 30);
  c.score = score;
  save();
}

function entEnd(el) {
  const c = ENTC, sc = c.score || 0, bad = c.qs.filter(q => (c.rate[q.id] || 0) < 2);
  const msg = sc >= 80 ? "Muito bom! Você está pronto para estas perguntas." : sc >= 50 ? "Bom caminho. Treine de novo as que ficaram no \"quase\"." : "Normal no começo. Reveja os tópicos e tente de novo amanhã.";
  let h = `<div class="card entres"><div class="eres" style="--p:${sc}"><b>${sc}%</b><span>${c.qs.length} pergunta${c.qs.length > 1 ? "s" : ""}</span></div><div><div class="q">Fim da entrevista</div><p class="mu">${msg}</p></div></div>`;
  h += `<h2>Suas respostas</h2>` + c.qs.map(q => { const r = c.rate[q.id] || 0; return `<div class="card eli"><span class="er">${ENT_RATE[r][0]}</span><div><b>${esc(q.q)}</b><span class="mu">${esc(q.tn)} · ${ENT_RATE[r][1]}</span>${r < 2 && q.tp ? `<button class="btn sm ghost" data-tp="${q.tp}">📖 Rever o tópico</button>` : ""}</div></div>` }).join("");
  h += `<div class="row">${bad.length ? `<button class="btn p" id="entbad">Treinar de novo as ${bad.length} que faltaram</button>` : ""}<button class="btn${bad.length ? "" : " p"}" id="entnew">Nova entrevista</button></div>`;
  h += rateCard("entrevista", "a simulação de entrevista");
  el.innerHTML = h;
  el.querySelectorAll("[data-tp]").forEach(b => b.onclick = () => openTopic(TOP.find(t => t.id == b.dataset.tp), "Estudar"));
  if ($("entbad")) $("entbad").onclick = () => entStart({ ids: bad.map(q => q.id), role: c.o.role });
  $("entnew").onclick = () => { ENTC = null; rEnt() };
  rateBind(el, () => entEnd(el));
}

function entSetup(el) {
  S.ent = S.ent || { hist: [], last: {} };
  ENTSET = ENTSET || { role: "sd", n: 5, rh: true, only: false };
  const B = entBank(), o = ENTSET, cnt = r => B.filter(x => x.area != "rh" && (r == "mix" || x.area == r)).length, any = TOP.some(t => tStatus(t) != "new");
  let h = `<div class="card entin"><div class="eav big">👩‍💼</div><div><div class="q">Como funciona</div><ol class="wl"><li><span>A entrevistadora faz a pergunta <b>em inglês</b>, como em muitas vagas. Toque em 🔊 para ouvir.</span></li><li><span>Você responde <b>falando</b> (o 🎤 escreve por você) ou digitando.</span></li><li><span>Compare com a <b>resposta modelo</b> e dê sua nota. O que faltou volta primeiro da próxima vez.</span></li></ol></div></div>`;
  h += `<h2>Para qual vaga?</h2><div class="eroles">` + Object.entries(ENT_ROLES).map(([k, [ic, t, d]]) => `<button class="note tc${o.role == k ? " on" : ""}" data-role="${k}"><span class="ic">${ic}</span><span class="tx"><b>${t}</b><span class="mu">${d} ${cnt(k)} perguntas.</span></span></button>`).join("") + `</div>`;
  h += `<h2>Quantas perguntas?</h2><div class="pills">${[3, 5, 8].map(x => `<button class="pill${o.n == x ? " on" : ""}" data-n="${x}">${x}${x == 3 ? " · rápida" : x == 8 ? " · completa" : ""}</button>`).join("")}</div>`;
  h += `<label class="it eopt"><input type="checkbox" id="entrh" ${o.rh ? "checked" : ""}><span>Começar com uma pergunta de RH (ex.: <i>Can you tell me a little about yourself?</i>)</span></label>`;
  if (any) h += `<label class="it eopt"><input type="checkbox" id="entonly" ${o.only ? "checked" : ""}><span>Só de tópicos que já comecei</span></label>`;
  h += `<div class="nextc"><button class="btn p" id="entgo">🎤 Começar a entrevista</button></div>`;
  const hist = (S.ent.hist || []).slice(0, 5);
  if (hist.length) h += `<h2>Suas últimas entrevistas</h2>` + hist.map(x => { const r = x.role.startsWith("topic:") ? (TOP.find(t => t.id == x.role.slice(6)) || { n: "tópico" }).n : (ENT_ROLES[x.role] || ENT_ROLES.mix)[1]; return `<div class="card eli"><span class="er">${x.s >= 80 ? "😃" : x.s >= 50 ? "🙂" : "😬"}</span><div><b>${x.s}% · ${esc(r)}</b><span class="mu">${x.d.split("-").reverse().join("/")} · ${x.n} perguntas</span></div></div>` }).join("");
  el.innerHTML = h;
  el.querySelectorAll("[data-role]").forEach(b => b.onclick = () => { o.role = b.dataset.role; entSetup(el) });
  el.querySelectorAll("[data-n]").forEach(b => b.onclick = () => { o.n = +b.dataset.n; entSetup(el) });
  $("entrh").onchange = e => { o.rh = e.target.checked };
  if ($("entonly")) $("entonly").onchange = e => { o.only = e.target.checked };
  $("entgo").onclick = () => entStart(o);
}

/* cartão no fim da explicação de um tópico */
function entCard(t) {
  const n = entBank().filter(x => x.tp == t.id).length;
  if (!n) return "";
  return `<div class="card entc"><div class="q">🎤 Treine para a entrevista</div><p class="mu">${n} pergunta${n > 1 ? "s" : ""} deste tópico que costuma${n > 1 ? "m" : ""} cair em entrevista. Responda falando e compare com a resposta modelo.</p><div class="row"><button class="btn" id="entt">Simular agora</button></div></div>`;
}

/* ---------- avaliação rápida (vai como feedback) ---------- */
const RATE_OPS = [["👍", "Gostei"], ["😐", "Mais ou menos"], ["👎", "Ficou confuso"]];
function rateCard(key, label) {
  S.rate = S.rate || {};
  const done = S.rate[key], p = RATEP[key];
  if (done) return `<div class="card rate ok"><span>${RATE_OPS[done.v][0]}</span><p class="mu">Obrigado pela avaliação! Ela ajuda a melhorar o curso.</p></div>`;
  let h = `<div class="card rate" data-rk="${esc(key)}"><div class="q">Como foi ${esc(label)}?</div><div class="rops">${RATE_OPS.map(([ic, t], v) => `<button class="${p && p.v === v ? "on" : ""}" data-rv="${v}"><span>${ic}</span>${t}</button>`).join("")}</div>`;
  if (p) h += `<textarea class="rtx" placeholder="Quer contar o porquê? (opcional) O que ajudou, o que confundiu, o que faltou...">${esc(p.txt || "")}</textarea><p class="mu rmsg"></p><div class="row"><button class="btn p" data-rsend="1">Enviar</button></div>`;
  return h + `</div>`;
}
function rateBind(el, again) {
  el.querySelectorAll(".rate[data-rk]").forEach(box => {
    const key = box.dataset.rk;
    box.querySelectorAll("[data-rv]").forEach(b => b.onclick = () => { RATEP[key] = { v: +b.dataset.rv, txt: (RATEP[key] || {}).txt || "" }; again() });
    const ta = box.querySelector(".rtx");
    if (ta) ta.oninput = () => { RATEP[key].txt = ta.value };
    const s = box.querySelector("[data-rsend]");
    if (s) s.onclick = async () => {
      const p = RATEP[key], A = window.soclabAccount, m = box.querySelector(".rmsg");
      if (!A) { m.textContent = "Sem conexão agora. Tente de novo daqui a pouco."; return }
      s.disabled = true; s.textContent = "Enviando…";
      try {
        await A.send(window.soclabWhere ? window.soclabWhere() : key, `Avaliação (${key}): ${RATE_OPS[p.v][0]} ${RATE_OPS[p.v][1]}` + (p.txt.trim() ? " · " + p.txt.trim() : ""));
        S.rate[key] = { v: p.v, d: new Date().toISOString().slice(0, 10) }; delete RATEP[key]; save(); again();
      } catch (e) { s.disabled = false; s.textContent = "Enviar"; m.textContent = "Não deu para enviar agora. Confira a internet e tente de novo." }
    };
  });
}

/* ---------- convite para entrar na conta (tela Hoje) ---------- */
function nudgeCard() {
  const A = window.soclabAccount;
  if (!A || !A.ready || A.user || (S.nudge || 0) > Date.now()) return "";
  const n = Object.values(S.tdone || {}).filter(Boolean).length + (S.hist || []).length + Object.keys(S.sd || {}).length + Object.keys(S.read || {}).length;
  if (n < 2) return "";
  return `<div class="card nudge"><span class="ni">☁️</span><div><div class="q">Seu progresso está só neste aparelho</div><p class="mu">Entre com seu e-mail para não perder nada e continuar no celular ou no computador. Sem senha: chega um código de 6 números.</p><div class="row"><button class="btn p" id="ndgo">Entrar com e-mail</button><button class="btn ghost" id="ndno">Agora não</button></div></div></div>`;
}
function nudgeBind(el, again) {
  if ($("ndgo")) $("ndgo").onclick = () => window.soclabAccount && window.soclabAccount.open();
  if ($("ndno")) $("ndno").onclick = () => { S.nudge = Date.now() + 7 * 864e5; save(); again() };
}
