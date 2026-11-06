// Conta: login por e-mail (código de 6 dígitos, sem senha) e progresso na nuvem (Supabase).
// Sem login tudo continua funcionando como antes: o progresso fica só neste navegador.
//
// O que é sincronizado:
//   - o curso (estudar.html): o estado salvo em localStorage "soclab-curso" (checklists, quiz, notas);
//   - o lab (index.html): os arquivos que o lab grava em /mnt/soclab (IndexedDB "/mnt", store FILE_DATA).
// A chave abaixo é a chave PÚBLICA (publishable) do projeto: ela só dá acesso ao que as regras (RLS) da
// tabela public.progress permitem, ou seja, cada pessoa lê e muda só a própria linha.
import { createClient } from "https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2.119.0/+esm";

const SUPABASE_URL = "https://vnmcjtdxfbjnxiuezzda.supabase.co";
const SUPABASE_KEY = "sb_publishable_JNaDfF2o5M0ibS1DGj0MKg_E8jWqvP_";
const COURSE_KEY = "soclab-curso";
const SYNC_KEY = "soclab-sync"; // {uid, dirty}: de quem é o progresso deste navegador e se falta enviar algo
const LAB_DIR = "/mnt/soclab/";

export const sb = createClient(SUPABASE_URL, SUPABASE_KEY, {
  auth: { storageKey: "soclab-auth", persistSession: true, autoRefreshToken: true, detectSessionInUrl: true },
});

// ---------------------------------------------------------------- arquivos do lab (IndexedDB do stlite)
// Mesmo formato que o Emscripten (IDBFS) usa: banco "/mnt" versão 21, store "FILE_DATA" sem keyPath,
// índice "timestamp"; pasta = {timestamp, mode: 16895}; arquivo = {timestamp, mode: 33206, contents}.
function openLabDb(create) {
  return new Promise((res) => {
    let q;
    try { q = indexedDB.open("/mnt", 21); } catch (e) { return res(null); }
    q.onupgradeneeded = () => {
      if (!create) { q.transaction.abort(); return; }
      const db = q.result;
      if (!db.objectStoreNames.contains("FILE_DATA"))
        db.createObjectStore("FILE_DATA").createIndex("timestamp", "timestamp", { unique: false });
    };
    q.onsuccess = () => {
      const db = q.result;
      if (!db.objectStoreNames.contains("FILE_DATA")) { db.close(); return res(null); }
      res(db);
    };
    q.onerror = () => res(null);
    q.onblocked = () => res(null);
  });
}

export async function readLabFiles() {
  const db = await openLabDb(false);
  if (!db) return {};
  return new Promise((res) => {
    const out = {};
    const tx = db.transaction("FILE_DATA");
    const c = tx.objectStore("FILE_DATA").openCursor();
    c.onsuccess = () => {
      const cur = c.result;
      if (!cur) return;
      const key = String(cur.key), v = cur.value;
      if (key.startsWith(LAB_DIR) && v && v.contents && !key.slice(LAB_DIR.length).includes("/")) {
        try { out[key.slice(LAB_DIR.length)] = new TextDecoder().decode(v.contents); } catch (e) {}
      }
      cur.continue();
    };
    tx.oncomplete = () => { db.close(); res(out); };
    tx.onerror = tx.onabort = () => { db.close(); res(out); };
  });
}

// Grava os arquivos (só antes de o lab abrir: o lab lê a pasta ao iniciar). clear=true apaga os demais.
async function writeLabFiles(files, clear) {
  const db = await openLabDb(true);
  if (!db) return;
  return new Promise((res) => {
    const tx = db.transaction("FILE_DATA", "readwrite");
    const st = tx.objectStore("FILE_DATA");
    const now = new Date();
    if (clear) st.delete(IDBKeyRange.bound(LAB_DIR, LAB_DIR + "￿"));
    st.put({ timestamp: now, mode: 16895 }, LAB_DIR.slice(0, -1));
    for (const [name, text] of Object.entries(files)) {
      if (!/^[\w.-]+$/.test(name)) continue;
      const b = new TextEncoder().encode(text);
      st.put({ timestamp: now, mode: 33206, contents: new Int8Array(b.buffer, b.byteOffset, b.length) }, LAB_DIR + name);
    }
    tx.oncomplete = () => { db.close(); res(); };
    tx.onerror = tx.onabort = () => { db.close(); res(); };
  });
}

// ---------------------------------------------------------------- juntar o que está aqui com o da nuvem
const isObj = (x) => x && typeof x === "object" && !Array.isArray(x);

// Desafios do terminal: resolvido em qualquer lugar conta como resolvido (união).
// Respostas do treino: vale a versão mais nova ("updated"). Outros casos: vale a deste navegador.
function mergeLabFile(name, cloud, here) {
  try {
    const a = JSON.parse(cloud), b = JSON.parse(here);
    if (/^terminal_[\w-]+\.json$/.test(name)) {
      const keys = [...new Set([...Object.keys(a), ...Object.keys(b)])];
      const out = {};
      for (const k of keys) out[k] = [...new Set([...(a[k] || []), ...(b[k] || [])])].sort();
      return JSON.stringify(out, null, 2);
    }
    if (a.updated && b.updated) return a.updated > b.updated ? cloud : here;
  } catch (e) {}
  return here;
}

export function mergeLab(cloud, here) {
  const out = { ...(isObj(cloud) ? cloud : {}) };
  for (const [name, text] of Object.entries(here || {}))
    out[name] = name in out ? mergeLabFile(name, out[name], text) : text;
  return out;
}

// Curso, primeira vez que a conta entra neste navegador: junta tudo (o daqui ganha nos valores simples).
export function mergeCourse(cloud, here) {
  if (Array.isArray(cloud) && Array.isArray(here)) return here.length >= cloud.length ? here : cloud;
  if (!isObj(cloud) || !isObj(here)) return here === undefined ? cloud : here;
  const out = { ...cloud };
  for (const [k, v] of Object.entries(here)) out[k] = k in cloud ? mergeCourse(cloud[k], v) : v;
  return out;
}

// ---------------------------------------------------------------- sincronização
const readJSON = (k, d) => { try { return JSON.parse(localStorage.getItem(k) || "") ?? d; } catch (e) { return d; } };
const syncState = () => readJSON(SYNC_KEY, {});
const setSync = (s) => localStorage.setItem(SYNC_KEY, JSON.stringify(s));
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

export async function currentUser() {
  const { data } = await sb.auth.getSession();
  return data.session ? data.session.user : null;
}

async function fetchRow(uid) {
  const { data, error } = await sb.from("progress").select("lab,course,updated_at").eq("user_id", uid).maybeSingle();
  if (error) throw error;
  return data;
}

async function pushRow(uid, lab, course) {
  const { error } = await sb.from("progress").upsert({ user_id: uid, lab, course });
  if (error) throw error;
}

let cloudLab = {}; // o lab como está na nuvem (o curso mostra os ✅ de desafios feitos em outro computador)
export const cloudLabFiles = () => cloudLab;

// Página do curso: traz o da nuvem, junta com o daqui e envia o resultado.
export async function syncCourse() {
  const user = await currentUser();
  if (!user) return null;
  const row = (await fetchRow(user.id)) || { lab: {}, course: {} };
  const s = syncState(), firstHere = s.uid !== user.id;
  const here = readJSON(COURSE_KEY, {});
  let course;
  if (firstHere) course = mergeCourse(row.course || {}, here);
  else if (s.dirty) course = here;
  else course = row.course && Object.keys(row.course).length ? row.course : here;
  const lab = mergeLab(row.lab || {}, await readLabFiles());
  if (!same(course, here)) localStorage.setItem(COURSE_KEY, JSON.stringify(course));
  if (!same(course, row.course) || !same(lab, row.lab)) await pushRow(user.id, lab, course);
  cloudLab = lab;
  setSync({ uid: user.id, dirty: false });
  return { user, changed: !same(course, here) };
}

// O curso mudou (save()): marca e envia daqui a pouco.
let timer = null;
export function courseChanged() {
  const s = syncState();
  if (!s.uid || leaving) return; // sem login
  setSync({ ...s, dirty: true });
  clearTimeout(timer);
  timer = setTimeout(() => pushCourse().catch(() => {}), 1500);
}

async function pushCourse() {
  const user = await currentUser();
  if (!user || syncState().uid !== user.id) return;
  const row = (await fetchRow(user.id)) || { lab: {}, course: {} };
  await pushRow(user.id, mergeLab(row.lab || {}, await readLabFiles()), readJSON(COURSE_KEY, {}));
  setSync({ uid: user.id, dirty: false });
  setStatus("ok");
}

// Página do lab, ANTES de abrir o lab: grava aqui o progresso da nuvem (com no máximo `ms` de espera).
export async function pullLabBeforeMount(ms = 5000) {
  const work = (async () => {
    const user = await currentUser();
    if (!user) return null;
    const row = await fetchRow(user.id);
    const here = await readLabFiles();
    const lab = mergeLab(row ? row.lab : {}, here);
    if (!same(lab, here)) await writeLabFiles(lab, false);
    return user;
  })().catch(() => null);
  return Promise.race([work, new Promise((r) => setTimeout(() => r(null), ms))]);
}

// Página do lab, depois de aberto: de tempos em tempos envia o que mudou nos arquivos do lab.
export function watchLab(everyMs = 15000) {
  let last = null;
  const tick = async () => {
    try {
      const user = await currentUser();
      if (!user) return;
      const here = await readLabFiles();
      if (last !== null && same(here, last)) return;
      const row = (await fetchRow(user.id)) || { lab: {}, course: {} };
      const lab = mergeLab(row.lab || {}, here);
      if (!same(lab, row.lab)) await pushRow(user.id, lab, row.course || {});
      last = here;
      setStatus("ok");
    } catch (e) { console.warn("conta.js: lab sync", e); setStatus("erro"); }
  };
  tick();
  setInterval(tick, everyMs);
  document.addEventListener("visibilitychange", () => { if (document.visibilityState === "hidden") tick(); });
}

// ---------------------------------------------------------------- entrar, sair, apagar
export async function sendCode(email) {
  const { error } = await sb.auth.signInWithOtp({ email, options: { shouldCreateUser: true } });
  if (error) throw error;
}

export async function verifyCode(email, token) {
  const { error } = await sb.auth.verifyOtp({ email, token, type: "email" });
  if (error) throw error;
}

// Nome que a pessoa escolheu (fica nos dados da conta, user_metadata.name).
export const nameOf = (user) => ((user && user.user_metadata && user.user_metadata.name) || "").trim();

export async function setName(name) {
  const { data, error } = await sb.auth.updateUser({ data: { name: name.trim().slice(0, 40) } });
  if (error) throw error;
  return data.user;
}

// Sair: o progresso fica na nuvem; este navegador volta a ficar vazio (computador compartilhado).
export async function signOut() {
  try { await pushCourse(); } catch (e) {}
  try { await sb.auth.signOut({ scope: "local" }); } catch (e) {}
  await clearHere();
}

export async function deleteAccount() {
  const { error } = await sb.rpc("delete_my_account");
  if (error) throw error;
  try { await sb.auth.signOut({ scope: "local" }); } catch (e) {}
  await clearHere();
}

let leaving = false; // saindo ou apagando: nada mais é gravado nem enviado até a página recarregar
async function clearHere() {
  leaving = true;
  clearTimeout(timer);
  localStorage.removeItem(COURSE_KEY);
  localStorage.removeItem(SYNC_KEY);
  localStorage.removeItem("soclab-auth");
  await writeLabFiles({}, true);
  cloudLab = {};
}

// ---------------------------------------------------------------- feedback e painel do admin
// Feedback: qualquer pessoa envia (com ou sem login); só o admin lê (regras na tabela public.feedback).
export async function sendFeedback(page, context, message) {
  const user = await currentUser();
  const row = { page, context: String(context || "").slice(0, 300), message: String(message).trim().slice(0, 2000) };
  if (user) row.user_id = user.id;
  const { error } = await sb.from("feedback").insert(row);
  if (error) throw error;
}

export async function isAdmin() {
  if (!(await currentUser())) return false;
  const { data, error } = await sb.rpc("is_admin");
  return !error && data === true;
}

// Para o painel: todas as contas com o progresso, e todo o feedback (o servidor recusa quem não é admin).
export async function adminData() {
  const [people, fb] = await Promise.all([
    sb.rpc("admin_overview"),
    sb.from("feedback").select("id,created_at,user_id,page,context,message,resolved").order("created_at", { ascending: false }).limit(500),
  ]);
  if (people.error) throw people.error;
  if (fb.error) throw fb.error;
  return { people: people.data || [], feedback: fb.data || [] };
}

export async function markFeedback(id, resolved) {
  const { error } = await sb.from("feedback").update({ resolved }).eq("id", id);
  if (error) throw error;
}

export async function deleteFeedback(id) {
  const { error } = await sb.from("feedback").delete().eq("id", id);
  if (error) throw error;
}

// ---------------------------------------------------------------- a parte visível
const CSS = `
.sc-chip{display:inline-flex;align-items:center;gap:8px;margin-left:auto;padding:8px 14px;border-radius:999px;border:1px solid rgba(255,255,255,.25);background:rgba(255,255,255,.08);color:inherit;font:600 14px var(--sans,system-ui);cursor:pointer;max-width:50%;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;text-decoration:none}
.sc-chip:hover{background:rgba(255,255,255,.16)}
.sc-dock{position:fixed;right:16px;bottom:16px;z-index:1000;display:flex;gap:8px;align-items:center}
.sc-float{background:#0e1b2a;color:#e8f1fa;border-color:#223244;max-width:280px;box-shadow:0 4px 14px rgba(0,0,0,.25);margin:0}
@media (max-width:999px){.sc-dock.curso{bottom:84px}}
.sc-in textarea{width:100%;box-sizing:border-box;min-height:130px;padding:12px 14px;border-radius:12px;border:1px solid var(--bd,#d6dee8);background:var(--sf,#fff);color:var(--tx,#101b28);font:15px/1.5 var(--sans,system-ui);margin-top:10px;resize:vertical}
.sc-ctx{font:12px var(--mono,monospace);color:var(--mu,#566478);background:rgba(127,127,127,.1);border-radius:8px;padding:6px 10px;margin-top:8px;word-break:break-word}
.sc-dlg{border:1px solid var(--bd,#d6dee8);border-radius:16px;padding:0;max-width:440px;width:calc(100% - 32px);background:var(--sf,#fff);color:var(--tx,#101b28);font:15px/1.5 var(--sans,system-ui)}
.sc-dlg::backdrop{background:rgba(0,0,0,.45)}
.sc-in{padding:22px}
.sc-in h2{margin:0 0 6px;font-size:20px}
.sc-in p{margin:8px 0}
.sc-mu{color:var(--mu,#566478);font-size:13px}
.sc-in input{width:100%;box-sizing:border-box;padding:12px 14px;border-radius:12px;border:1px solid var(--bd,#d6dee8);background:var(--sf,#fff);color:var(--tx,#101b28);font:16px var(--sans,system-ui);margin:10px 0 0;height:auto}
.sc-in input.sc-code{font:600 24px var(--mono,monospace);letter-spacing:8px;text-align:center}
.sc-row{display:flex;gap:10px;margin-top:14px;flex-wrap:wrap}
.sc-b{flex:1;min-height:44px;padding:10px 14px;border-radius:12px;border:1px solid var(--bd,#d6dee8);background:var(--sf,#fff);color:var(--tx,#101b28);font:600 15px var(--sans,system-ui);cursor:pointer}
.sc-b.p{background:var(--ac,#0f766e);color:var(--onac,#fff);border-color:var(--ac,#0f766e)}
.sc-b.r{background:transparent;color:var(--bad,#b91c1c);border-color:var(--bad,#b91c1c)}
.sc-b:disabled{opacity:.6;cursor:default}
.sc-err{color:var(--bad,#b91c1c);font-size:14px;min-height:1em}
.sc-in a{color:var(--ac,#0f766e)}
.sc-in hr{border:0;border-top:1px solid var(--bd,#d6dee8);margin:18px 0 12px}
`;

let chip = null, statusText = "";
function setStatus(s) {
  statusText = s === "ok" ? "salvo na nuvem" : s === "erro" ? "sem conexão: salvo só aqui" : "";
  if (chip && chip.dataset.email) chip.title = chip.dataset.email + (statusText ? " · " + statusText : "");
}

function el(html) {
  const t = document.createElement("template");
  t.innerHTML = html.trim();
  return t.content.firstElementChild;
}
const escHtml = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

function friendly(err) {
  const m = String((err && (err.code || err.message)) || err);
  if (/rate|429|seconds/i.test(m)) return "Muitos pedidos seguidos. Espere um minuto e tente de novo.";
  if (/not_authorized|not authorized/i.test(m)) return "Ainda não dá para mandar e-mail para este endereço (o envio de e-mails do site ainda está sendo configurado).";
  if (/expired|invalid|otp/i.test(m)) return "Código errado ou vencido. Confira o último e-mail ou peça outro código.";
  if (/fetch|network/i.test(m)) return "Sem conexão com o servidor. Confira a internet e tente de novo.";
  return "Não deu certo: " + m;
}

// Janela de entrar / conta. onChange é chamado depois de entrar, sair ou apagar.
function openDialog(onChange) {
  let dlg = document.getElementById("sc-dlg");
  if (!dlg) {
    dlg = el(`<dialog class="sc-dlg" id="sc-dlg" aria-labelledby="sc-title"><div class="sc-in"></div></dialog>`);
    document.body.appendChild(dlg);
    dlg.addEventListener("click", (e) => { if (e.target === dlg) dlg.close(); });
  }
  const box = dlg.querySelector(".sc-in");
  const privacy = `<p class="sc-mu">Guardamos só o seu e-mail, o nome que você escolher e o seu progresso (checklists, quiz, notas e desafios do lab), em servidores do Supabase nos Estados Unidos. O dono do site pode ver o progresso para acompanhar os testes. Nada é vendido ou usado para propaganda. <a href="privacidade.html" target="_blank" rel="noopener">Aviso de privacidade</a></p>`;

  const showEmail = (msg = "") => {
    box.innerHTML = `<h2 id="sc-title">Entrar</h2>
      <p>Salve seu progresso na nuvem e continue em qualquer computador. Não tem senha: enviamos um código de 6 dígitos para o seu e-mail.</p>
      <form id="sc-f1"><label for="sc-email" class="sc-mu">Seu e-mail</label>
      <input id="sc-email" type="email" autocomplete="email" required placeholder="voce@exemplo.com">
      <p class="sc-err" id="sc-err">${escHtml(msg)}</p>
      <div class="sc-row"><button type="button" class="sc-b" id="sc-x">Agora não</button><button class="sc-b p" id="sc-send">Enviar código</button></div></form>
      ${privacy}`;
    box.querySelector("#sc-x").onclick = () => dlg.close();
    box.querySelector("#sc-f1").onsubmit = async (e) => {
      e.preventDefault();
      const email = box.querySelector("#sc-email").value.trim().toLowerCase();
      const b = box.querySelector("#sc-send");
      b.disabled = true; b.textContent = "Enviando…";
      try { await sendCode(email); showCode(email); }
      catch (err) { box.querySelector("#sc-err").textContent = friendly(err); b.disabled = false; b.textContent = "Enviar código"; }
    };
    setTimeout(() => box.querySelector("#sc-email")?.focus(), 50);
  };

  const showCode = (email) => {
    box.innerHTML = `<h2 id="sc-title">Digite o código</h2>
      <p>Mandamos um código de 6 dígitos para <b>${escHtml(email)}</b>. Pode levar um minuto; veja também a caixa de spam.</p>
      <form id="sc-f2"><input id="sc-code" class="sc-code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6,10}" maxlength="10" required aria-label="Código de 6 dígitos">
      <p class="sc-err" id="sc-err"></p>
      <div class="sc-row"><button type="button" class="sc-b" id="sc-back">Trocar e-mail</button><button class="sc-b p" id="sc-ok">Entrar</button></div></form>
      <p class="sc-mu">Não chegou? <a href="#" id="sc-again">Enviar outro código</a></p>`;
    box.querySelector("#sc-back").onclick = () => showEmail();
    box.querySelector("#sc-again").onclick = async (e) => {
      e.preventDefault();
      try { await sendCode(email); box.querySelector("#sc-err").textContent = "Código novo enviado."; }
      catch (err) { box.querySelector("#sc-err").textContent = friendly(err); }
    };
    box.querySelector("#sc-f2").onsubmit = async (e) => {
      e.preventDefault();
      const b = box.querySelector("#sc-ok");
      b.disabled = true; b.textContent = "Entrando…";
      try {
        await verifyCode(email, box.querySelector("#sc-code").value.trim());
        const u = await currentUser();
        if (u && !nameOf(u)) return showName(true);
        dlg.close();
        await onChange();
      } catch (err) { box.querySelector("#sc-err").textContent = friendly(err); b.disabled = false; b.textContent = "Entrar"; }
    };
    setTimeout(() => box.querySelector("#sc-code")?.focus(), 50);
  };

  const showName = (first) => {
    box.innerHTML = `<h2 id="sc-title">${first ? "Bem-vindo! 👋" : "Seu nome"}</h2>
      <p>Como você quer ser chamado? O nome aparece no topo do curso.</p>
      <form id="sc-f3"><input id="sc-name" type="text" autocomplete="given-name" maxlength="40" required placeholder="Seu nome">
      <p class="sc-err" id="sc-err"></p>
      <div class="sc-row"><button type="button" class="sc-b" id="sc-skip">${first ? "Pular" : "Cancelar"}</button><button class="sc-b p" id="sc-save">Salvar</button></div></form>`;
    const done = async () => { dlg.close(); await onChange(); };
    box.querySelector("#sc-skip").onclick = done;
    box.querySelector("#sc-f3").onsubmit = async (e) => {
      e.preventDefault();
      try { await setName(box.querySelector("#sc-name").value); await done(); }
      catch (err) { box.querySelector("#sc-err").textContent = friendly(err); }
    };
    setTimeout(() => box.querySelector("#sc-name")?.focus(), 50);
  };

  const showAccount = (user) => {
    box.innerHTML = `<h2 id="sc-title">Sua conta</h2>
      <p>${nameOf(user) ? `Olá, <b>${escHtml(nameOf(user))}</b>! ` : ""}Você entrou como <b>${escHtml(user.email)}</b> (<a href="#" id="sc-rename">${nameOf(user) ? "mudar nome" : "colocar seu nome"}</a>). Seu progresso do curso e do lab é salvo na nuvem.${statusText.startsWith("sem") ? ` <b>Agora: ${escHtml(statusText)}.</b>` : ""}</p>
      <p class="sc-err" id="sc-err"></p>
      <div class="sc-row"><button class="sc-b" id="sc-x">Fechar</button><button class="sc-b p" id="sc-out">Sair</button></div>
      <p class="sc-mu">Ao sair, o progresso continua salvo na sua conta e some deste navegador (bom para computador compartilhado).</p>
      <div id="sc-admin"></div>
      <hr>${privacy}
      <div class="sc-row"><button class="sc-b r" id="sc-del">Apagar minha conta</button></div>`;
    box.querySelector("#sc-x").onclick = () => dlg.close();
    isAdmin().then((yes) => {
      const slot = box.querySelector("#sc-admin");
      if (!yes || !slot) return;
      slot.innerHTML = `<div class="sc-row"><button class="sc-b p" id="sc-adm">📊 Painel do admin</button></div>`;
      slot.querySelector("#sc-adm").onclick = () => {
        dlg.close();
        if (window.soclabOpenAdmin) window.soclabOpenAdmin(); else location.href = "estudar.html#admin";
      };
    });
    box.querySelector("#sc-rename").onclick = (e) => { e.preventDefault(); showName(false); };
    box.querySelector("#sc-out").onclick = async () => {
      await signOut();
      location.reload(); // a página volta ao estado sem login (nada do progresso antigo fica na memória)
    };
    box.querySelector("#sc-del").onclick = async () => {
      const typed = prompt('Isto apaga para sempre a sua conta e todo o progresso salvo (na nuvem e neste navegador).\n\nPara confirmar, digite APAGAR:');
      if ((typed || "").trim().toUpperCase() !== "APAGAR") return;
      try { await deleteAccount(); alert("Conta apagada."); location.reload(); }
      catch (err) { box.querySelector("#sc-err").textContent = friendly(err); }
    };
  };

  currentUser().then((u) => (u ? showAccount(u) : showEmail()));
  if (!dlg.open) dlg.showModal();
}

function addStyle() {
  if (document.getElementById("sc-css")) return;
  const s = document.createElement("style");
  s.id = "sc-css";
  s.textContent = CSS;
  document.head.appendChild(s);
}

function paintChip(user) {
  chip.dataset.email = user ? user.email : "";
  chip.textContent = user ? "☁️ " + (nameOf(user) || user.email) : "☁️ Entrar e salvar na nuvem";
  setStatus(statusText ? (statusText.startsWith("salvo") ? "ok" : "erro") : "");
}

// Janela "Dar feedback". where(): onde a pessoa está (vai junto com a mensagem).
function openFeedback(page, where) {
  let dlg = document.getElementById("sc-fb");
  if (!dlg) {
    dlg = el(`<dialog class="sc-dlg" id="sc-fb" aria-labelledby="sc-fbt"><div class="sc-in"></div></dialog>`);
    document.body.appendChild(dlg);
    dlg.addEventListener("click", (e) => { if (e.target === dlg) dlg.close(); });
  }
  const box = dlg.querySelector(".sc-in");
  let ctx = "";
  try { ctx = String(where() || "").slice(0, 300); } catch (e) {}
  box.innerHTML = `<h2 id="sc-fbt">Dar feedback</h2>
    <p>Achou um erro? Algo ficou confuso? Tem uma ideia? Conta aqui. Vai direto para quem cuida do curso.</p>
    <form id="sc-ff"><textarea id="sc-msg" maxlength="2000" required placeholder="Ex.: no desafio linux-03 eu não entendi o que é para responder."></textarea>
    ${ctx ? `<div class="sc-ctx">Vai junto: ${escHtml(ctx)}</div>` : ""}
    <p class="sc-err" id="sc-err"></p>
    <div class="sc-row"><button type="button" class="sc-b" id="sc-fx">Cancelar</button><button class="sc-b p" id="sc-fs">Enviar</button></div></form>
    <p class="sc-mu" id="sc-who"></p>`;
  currentUser().then((u) => {
    const w = box.querySelector("#sc-who");
    if (w) w.textContent = u ? `Enviado como ${nameOf(u) || u.email}.` : "Você não entrou na conta: o feedback vai sem nome. Se quiser resposta, escreva seu contato na mensagem.";
  });
  box.querySelector("#sc-fx").onclick = () => dlg.close();
  box.querySelector("#sc-ff").onsubmit = async (e) => {
    e.preventDefault();
    const b = box.querySelector("#sc-fs");
    b.disabled = true; b.textContent = "Enviando…";
    try {
      await sendFeedback(page, ctx, box.querySelector("#sc-msg").value);
      box.innerHTML = `<h2>Obrigado! 🙌</h2><p>Seu feedback foi enviado.</p><div class="sc-row"><button class="sc-b p" id="sc-fok">Fechar</button></div>`;
      box.querySelector("#sc-fok").onclick = () => dlg.close();
    } catch (err) { box.querySelector("#sc-err").textContent = friendly(err); b.disabled = false; b.textContent = "Enviar"; }
  };
  if (!dlg.open) dlg.showModal();
  setTimeout(() => box.querySelector("#sc-msg")?.focus(), 50);
}

function dock(page, where) {
  const d = el(`<div class="sc-dock ${page}"><button type="button" class="sc-chip sc-float" id="sc-fbb">💬 Feedback</button></div>`);
  d.querySelector("#sc-fbb").onclick = () => openFeedback(page, where);
  document.body.appendChild(d);
  return d;
}

// Página do curso. onReload: o progresso daqui mudou (veio da nuvem, ou a conta saiu): redesenhe.
export async function mountCourse(onReload) {
  addStyle();
  chip = el(`<button class="sc-chip sc-float" type="button" id="sc-chip"></button>`);
  const hi = document.querySelector("#hero .hi"), av = document.querySelector("#hero .av");
  const greet = (user) => {
    const n = nameOf(user);
    if (hi) hi.textContent = n ? `Olá, ${n}! Bons estudos` : "Olá! Bons estudos";
    if (av) av.textContent = n ? n[0].toUpperCase() : "S";
  };
  const refresh = async () => {
    const user = await currentUser();
    greet(user);
    paintChip(user);
    if (user) {
      try { const r = await syncCourse(); setStatus("ok"); if (r) onReload(); }
      catch (e) { setStatus("erro"); }
    } else onReload();
    paintChip(user);
  };
  chip.onclick = () => openDialog(refresh);
  dock("curso", () => (window.soclabWhere ? window.soclabWhere() : "")).appendChild(chip);
  const fromHash = () => {
    if (location.hash === "#conta") { history.replaceState(null, "", location.pathname); openDialog(refresh); }
    if (location.hash === "#admin" && window.soclabOpenAdmin) { history.replaceState(null, "", location.pathname); window.soclabOpenAdmin(); }
  };
  window.addEventListener("hashchange", fromHash);
  fromHash();
  await refresh();
  // de volta de outra aba (o lab): pega o que o lab enviou
  window.addEventListener("focus", () => currentUser().then((u) => u && syncCourse().then(onReload).catch(() => {})));
}

// Onde a pessoa está no lab: a aba aberta e o título do desafio (o melhor que dá para ler da página).
function labWhere() {
  const tab = document.querySelector('[role="tab"][aria-selected="true"]');
  const panel = document.querySelector('[role="tabpanel"]:not([hidden])') || document;
  // o desafio escolhido (caixa "Desafio": "linux-01 · Qual o tamanho do log?"); senão, o primeiro título
  const pick = [...panel.querySelectorAll('[data-testid="stSelectbox"] input')].map((x) => (x.value || x.getAttribute("aria-label") || "").trim())
    .find((t) => /\b(linux|ps|cmd)-\d+/.test(t));
  const head = pick || [...panel.querySelectorAll("h2, h3")].map((x) => x.textContent.trim()).find(Boolean);
  return ["Lab", tab && tab.textContent.trim(), head].filter(Boolean).join(" · ");
}

// Página do lab: só um botão no canto (a conta é gerenciada nas páginas do curso).
export async function mountLab(user) {
  addStyle();
  chip = el(`<a class="sc-chip sc-float" id="sc-chip" href="estudar.html#conta"></a>`);
  dock("lab", labWhere).appendChild(chip);
  paintChip(user);
  if (!user) chip.title = "Sem login o progresso fica só neste navegador. Entre pelas páginas do curso.";
}
