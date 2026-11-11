/* ===== Fila de chamados do Service Desk (curso/chamados.js; os chamados vêm de curso/chamados.py) =====
   Cada chamado: triagem → perguntas ao usuário → diagnóstico no terminal → solução → nota do ticket.
   O resultado fica em S.sd[id] = {b: melhor nota, n: tentativas, u: última nota}. Nota 70+ = resolvido. */
const TK_IMP=["","Uma pessoa","Um setor ou grupo","A empresa ou um serviço crítico"];
const TK_URG=["","Baixa: dá para esperar","Média: atrapalha, mas a pessoa trabalha","Alta: parou ou tem prazo agora"];
const TK_PN={1:"P1 · Crítica",2:"P2 · Alta",3:"P3 · Média",4:"P4 · Baixa"};
const TK_SLA={1:["15 min","4 h"],2:["30 min","8 h"],3:["4 h","2 dias úteis"],4:["1 dia útil","5 dias úteis"]};
const TK_STEPS=["Triagem","Perguntas","Diagnóstico","Solução","Nota"];
const TK_W=[25,20,15,25,15];
const TK_NIV={1:"Nível 1",2:"Nível 2",3:"Nível 3"};
const SDTXT="Praticar na Fila de chamados: resolver os chamados deste tópico (nota 70 ou mais)";
const FILA={};TK.forEach(t=>t.topicos.forEach(p=>(FILA[p]=FILA[p]||[]).push(t)));
let TKF="todos",TKC=null;
function tkPri(i,u){const s=i+u;return s>=6?1:s==5?2:s==4?3:4}
function tkRes(id){return (S.sd||{})[id]}
function tkOk(id){const r=tkRes(id);return !!r&&r.b>=70}
function tkNorm(s){return String(s).toLowerCase().replace(/\s+/g," ").trim()}
/* tópicos: a etapa Praticar soma os desafios do lab e os chamados da fila */
function filaCount(t){const L=FILA[t.id]||[];return [L.filter(x=>tkOk(x.id)).length,L.length]}
function pratCount(t){const a=LAB[t.id]?labCount(t):[0,0],b=filaCount(t);return [a[0]+b[0],a[1]+b[1]]}
function sdTick(){TOP.forEach(t=>{if(!FILA[t.id])return;let k=t.chk.indexOf(SDTXT);if(k<0){t.chk.push(SDTXT);k=t.chk.length-1}
const [d,n]=filaCount(t);if(n&&d==n&&!S.tdone[t.id+"-"+k]){S.tdone[t.id+"-"+k]=true;save()}})}
function sdCard(t){const [d,n]=filaCount(t);return `<div class="card labc sdc"><div class="q">🎧 Agora atenda chamados</div><p class="mu">${n} chamado${n>1?"s":""} da Fila de chamados usa${n>1?"m":""} este assunto (${d} resolvido${d==1?"":"s"}).</p></div>`}
function sdPrat(t){const L=FILA[t.id],[d,n]=filaCount(t);let h=`<div class="card"><div class="q">${d} de ${n} chamados resolvidos</div><span class="bar" style="margin-top:10px"><i style="width:${n?100*d/n:0}%"></i></span><p class="mu" style="margin-bottom:0">Chamados da Fila que usam este tópico. Resolvido = nota 70 ou mais. Com todos resolvidos, o item do Checklist se marca sozinho.</p></div><h3 style="margin:18px 2px 8px;font-size:15px">🎧 Fila de chamados</h3>`;
return h+L.map(x=>{const r=tkRes(x.id),ok=tkOk(x.id);return `<button class="note${ok?" on":""}" data-tkgo="${x.id}" style="display:flex;gap:12px;align-items:center;width:100%;text-align:left"><span style="flex:none;width:22px">${ok?"✅":"⬜"}</span><span class="ph" style="flex:none">${esc(x.id)}</span><span style="flex:1;min-width:0">${esc(x.titulo)}<span class="mu" style="display:block;font-weight:400">${TK_NIV[x.nivel]}${r?" · melhor nota "+r.b:""}</span></span><span class="ch" style="font-size:22px;color:var(--mu)">›</span></button>`}).join("")}
document.addEventListener("click",e=>{const b=e.target.closest("[data-tkgo]");if(b){const t=TK.find(x=>x.id==b.dataset.tkgo);if(t){goTab(9);tkStart(t)}}});
/* ---------- a fila ---------- */
function rSd(){if(TKC)return tkRender();const el=$("v9");S.sd=S.sd||{};
const done=TK.filter(t=>tkOk(t.id)).length,tried=TK.filter(t=>tkRes(t.id)),avg=tried.length?Math.round(tried.reduce((a,t)=>a+tkRes(t.id).b,0)/tried.length):0,nx=TK.find(t=>!tkOk(t.id));
let h=`<div class="sdhero"><div class="sdh1"><span class="k">Seu turno no Service Desk</span><b>${done} de ${TK.length} chamados resolvidos</b><span class="bar"><i style="width:${100*done/TK.length}%"></i></span><span class="sdh2">${tried.length?"Média das suas notas: "+avg+" de 100":"Ninguém atendeu a fila ainda. Comece pelo primeiro."}</span></div>${nx?`<button class="btn p" id="sdnx">Atender ${esc(nx.id)} →</button>`:`<span class="sdh2">🎉 Fila zerada! Refaça para melhorar as notas.</span>`}</div>`;
h+=`<details class="card sdhow"${tried.length?"":" open"}><summary><b>Como funciona</b><span class="mu"> · 5 etapas, como no primeiro emprego de TI</span></summary><ol class="sdsteps"><li><b>Triagem</b><span>Tipo, categoria, impacto e urgência. A prioridade sai da matriz.</span></li><li><b>Perguntas</b><span>Escolha até 3 perguntas para o usuário. Umas ajudam, outras atrapalham.</span></li><li><b>Diagnóstico</b><span>Rode comandos no terminal e descubra a causa pela saída.</span></li><li><b>Solução</b><span>Resolver no N1, escalar ou acionar a Segurança.</span></li><li><b>Nota</b><span>Escreva a nota do ticket, em português ou inglês.</span></li></ol><p class="mu" style="margin:0">Tudo é fictício, mas baseado nos chamados mais comuns de um Service Desk. Nota 70 ou mais = resolvido. Estude antes: tópicos <a href="#sd">O que é Service Desk</a>, <a href="#atend">Atendimento</a>, <a href="#trouble">Troubleshooting</a> e <a href="#contas">Contas e acessos</a>.</p></details>`;
const F=[["todos","Todos"],["1","Nível 1"],["2","Nível 2"],["3","Nível 3"],["abertos","Não resolvidos"]];
h+=`<div class="sdfil" role="group" aria-label="Filtrar a fila">${F.map(([k,n])=>`<button class="pill${TKF==k?" on":""}" data-f="${k}">${n}</button>`).join("")}</div>`;
const L=TK.filter(t=>TKF=="todos"||(TKF=="abertos"?!tkOk(t.id):String(t.nivel)==TKF));
h+=`<div class="sdq"><div class="sdqh"><span>Número</span><span>Resumo</span><span>Canal</span><span>Nível</span><span>Estado</span></div>`+L.map(t=>{const r=tkRes(t.id),ok=tkOk(t.id),st=ok?`<span class="sdst ok">Resolvido · ${r.b}</span>`:r?`<span class="sdst re">Reaberto · ${r.b}</span>`:`<span class="sdst nw">Novo</span>`;
return `<button class="sdr${ok?" ok":""}" data-tk="${t.id}"><span class="sdn">${esc(t.id)}</span><span class="sdt"><b>${esc(t.titulo)}</b><span class="mu">${esc(t.quem)} · ${esc(t.setor)} · ${esc(t.hora)}</span></span><span class="sdc2">${esc(t.canal)}</span><span class="sdlv">${"●".repeat(t.nivel)}<i>${"●".repeat(3-t.nivel)}</i></span>${st}</button>`}).join("")+(L.length?"":`<p class="mu" style="padding:14px">Nenhum chamado neste filtro.</p>`)+`</div>`;
$("v9").innerHTML=h;
if($("sdnx"))$("sdnx").onclick=()=>tkStart(nx);
$("v9").querySelectorAll("[data-f]").forEach(b=>b.onclick=()=>{TKF=b.dataset.f;rSd()});
$("v9").querySelectorAll("[data-tk]").forEach(b=>b.onclick=()=>tkStart(TK.find(t=>t.id==b.dataset.tk)))}
/* ---------- um chamado ---------- */
function tkStart(t){TKC={t,i:0,tri:{},ask:{sel:[],ord:shuf(t.perguntas.map((_,k)=>k))},hist:[],diag:{opts:shuf(t.diag.ops.map((x,k)=>[x,k==0]))},acao:{opts:shuf(t.acao.ops.map((x,k)=>[x,k==0]))},nota:{txt:""},pts:[null,null,null,null,null]};rSd();window.scrollTo(0,0)}
function tkHead(){const c=TKC,t=c.t,p=c.pts[0]!=null?tkPri(t.triagem.impacto,t.triagem.urgencia):null,stt=c.i>=5?(c.pts.reduce((x,y)=>x+y,0)>=69.5?"Resolvido":"Reaberto"):c.i==0?"Novo":"Em andamento";
let h=`<button class="btn bk" id="tkbk">← Fila</button><div class="tkf"><div class="tkft"><span class="tkid">${esc(t.id)}</span><h2>${esc(t.titulo)}</h2></div><div class="tkg"><div><span>Solicitante</span><b>${esc(t.quem)}</b></div><div><span>Setor</span><b>${esc(t.setor)}</b></div><div><span>Canal</span><b>${esc(t.canal)}</b></div><div><span>Aberto às</span><b>${esc(t.hora)}</b></div><div><span>Estado</span><b>${stt}</b></div><div><span>Prioridade</span><b>${p?`<span class="pri p${p}">${TK_PN[p]}</span>`:"—"}</b></div></div><div class="tkmsg"><span class="k">Descrição</span>${esc(t.msg).replace(/\n/g,"<br>")}</div></div>`;
h+=`<div class="steps tks">`+TK_STEPS.map((s,k)=>`<button disabled class="${k==c.i?"on":""}${c.pts[k]!=null?" ok":""}"><span class="sn">${c.pts[k]!=null?"✓":k+1}</span><span class="sl">${s}</span></button>`).join("")+`</div>`;return h}
function tkNext(label){return `<div class="nextc"><button class="btn p" id="tknx">${label}</button></div>`}
function tkRender(){const el=$("v9"),c=TKC,t=c.t;let h=tkHead();
if(c.i==0)h+=tkTri();else if(c.i==1)h+=tkAsk();else if(c.i==2)h+=tkDiag();else if(c.i==3)h+=tkAcao();else if(c.i==4)h+=tkNota();else h+=tkFim();
el.innerHTML=h;$("tkbk").onclick=()=>{TKC=null;rSd();window.scrollTo(0,0)};
if($("tknx"))$("tknx").onclick=()=>{c.i++;tkRender();window.scrollTo(0,0)};
tkBind()}
function tkPills(f,vals,labels){const v=TKC.tri[f],lock=TKC.pts[0]!=null;return `<div class="pills" data-f="${f}">`+vals.map((x,k)=>`<button class="pill${v==x?" on":""}" data-v="${esc(x)}"${lock?" disabled":""}>${esc(labels?labels[k]:x)}</button>`).join("")+`</div>`}
function tkTri(){const c=TKC,t=c.t,r=c.tri,T=t.triagem;let h=`<div class="card"><div class="q">1. Triagem</div><p class="mu">Classifique o chamado como você faria no sistema de tickets. A prioridade sai da matriz impacto × urgência.</p>
<div class="sdfld"><label>Tipo</label>${tkPills("tipo",TK_TIPOS)}</div><div class="sdfld"><label>Categoria</label>${tkPills("cat",TK_CATS)}</div>
<div class="sdfld"><label>Impacto: quem é afetado?</label>${tkPills("imp",["1","2","3"],TK_IMP.slice(1))}</div><div class="sdfld"><label>Urgência: dá para esperar?</label>${tkPills("urg",["1","2","3"],TK_URG.slice(1))}</div>`;
const pr=r.imp&&r.urg?tkPri(+r.imp,+r.urg):null;h+=`<div class="sdpri">Prioridade calculada: ${pr?`<span class="pri p${pr}">${TK_PN[pr]}</span>`:"<span class='mu'>escolha impacto e urgência</span>"}</div>`;
if(c.pts[0]==null)return h+`<div class="row"><button class="btn p" id="trok"${r.tipo&&r.cat&&r.imp&&r.urg?"":" disabled"}>Confirmar triagem</button></div></div>`;
const cats=[].concat(T.cat),ep=tkPri(T.impacto,T.urgencia),rows=[["Tipo",r.tipo,T.tipo,r.tipo==T.tipo],["Categoria",r.cat,cats.join(" ou "),cats.includes(r.cat)],["Impacto",TK_IMP[r.imp],TK_IMP[T.impacto],+r.imp==T.impacto],["Urgência",TK_URG[r.urg],TK_URG[T.urgencia],+r.urg==T.urgencia]];
h+=`<table class="sdres"><tr><th></th><th>Você</th><th>Esperado</th></tr>${rows.map(x=>`<tr class="${x[3]?"g":"r"}"><td>${x[3]?"✅":"❌"} ${x[0]}</td><td>${esc(x[1])}</td><td>${esc(x[2])}</td></tr>`).join("")}</table><div class="a"><b>Prioridade certa: ${TK_PN[ep]}.</b><p>${esc(T.porque)}</p><p class="mu" style="margin:0">SLA típico de ${TK_PN[ep].split(" ")[0]}: primeira resposta em ${TK_SLA[ep][0]}, solução em ${TK_SLA[ep][1]}.</p></div></div>`+tkNext("Próximo: perguntas ao usuário →");return h}
function tkAsk(){const c=TKC,t=c.t,A=c.ask,P=t.perguntas,good=P.filter(q=>q.ok).length;let h=`<div class="card"><div class="q">2. Perguntas ao usuário</div>`;
if(c.pts[1]==null){h+=`<p class="mu">Escolha até 3 perguntas para fazer a ${esc(t.quem.split(" ")[0])}. As respostas vão te ajudar no diagnóstico.</p>`+A.ord.map(k=>{const on=A.sel.includes(k);return `<label class="it askq${on?" d":""}"><input type="checkbox" data-q="${k}"${on?" checked":""}${!on&&A.sel.length>=3?" disabled":""}><span>${esc(P[k].p)}</span></label>`}).join("")+`<div class="row"><button class="btn p" id="askok"${A.sel.length?"":" disabled"}>Perguntar (${A.sel.length} de 3)</button></div></div>`;return h}
h+=`<div class="chat">`+A.sel.map(k=>{const q=P[k];return `<div class="me">${esc(q.p)}</div><div class="them"><span class="who">${esc(t.quem)}</span>${esc(q.r)}</div><div class="verd ${q.ok?"g":"r"}">${q.ok?"✅ Boa pergunta.":"❌ Não ajudou."} ${esc(q.porque)}</div>`}).join("")+`</div>`;
const miss=P.filter((q,k)=>q.ok&&!A.sel.includes(k));if(miss.length)h+=`<details class="sdmiss"><summary>${miss.length==1?"Uma pergunta útil que você não fez":miss.length+" perguntas úteis que você não fez"} (e as respostas)</summary>${miss.map(q=>`<p><b>${esc(q.p)}</b><br>${esc(q.r)}<br><span class="mu">${esc(q.porque)}</span></p>`).join("")}</details>`;
const g=A.sel.filter(k=>P[k].ok).length;h+=`<p class="mu" style="margin-bottom:0">${g} de ${Math.min(3,good)} perguntas úteis.</p></div>`+tkNext("Próximo: diagnóstico →");return h}
function tkOut(){return TKC.hist.map(([cmd,out])=>`<div class="tl"><span class="tp">${esc(TKC.t.terminal.prompt)}</span> ${esc(cmd)}</div><pre>${esc(out)}</pre>`).join("")}
function tkRun(raw){const c=TKC,T=c.t.terminal,n=tkNorm(raw);if(!n)return;if(n=="cls"||n=="clear"){c.hist=[];return}
let m=T.cmds.find(x=>tkNorm(x.c)==n||(x.a||[]).some(a=>tkNorm(a)==n));
if(!m){const w=n.split(" ")[0],s=T.cmds.filter(x=>tkNorm(x.c).split(" ")[0]==w);if(s.length==1)m=s[0]}
if(n=="help"||n=="ajuda"||n=="?")c.hist.push([raw,"Comandos que funcionam neste chamado:\n"+T.cmds.map(x=>"  "+x.c).join("\n")]);
else if(m){c.hist.push([raw,m.out]);c.ran=1}
else c.hist.push([raw,"'"+raw.trim()+"' não está disponível neste chamado (o terminal é simulado).\nDigite help para ver os comandos, ou clique num deles acima."])}
function tkMC(key,num,title,Q){const c=TKC,X=c[key];let h=`<div class="q" style="margin-top:4px">${esc(Q.p)}</div><div class="ops">`+X.opts.map(([x,ok],k)=>`<button class="btn op${X.pick!=null?(ok?" g":X.pick==k?" r":""):""}" data-mc="${key}" data-k="${k}"${X.pick!=null?" disabled":""}>${esc(x)}</button>`).join("")+`</div>`;
if(X.pick!=null)h+=`<div class="a"><b>${X.opts[X.pick][1]?"Isso mesmo.":"Não é a melhor resposta."}</b><p>${esc(Q.porque)}</p></div>`;return h}
function tkDiag(){const c=TKC,T=c.t.terminal;let h=`<div class="card"><div class="q">3. Diagnóstico</div><p class="mu">${esc(T.onde)} Clique num comando ou digite (help mostra a lista).</p><div class="tkchips">${T.cmds.map((x,k)=>`<button class="tkchip" data-run="${k}">${esc(x.c)}</button>`).join("")}</div>
<div class="term" id="term"><div id="tout">${c.hist.length?tkOut():`<div class="mu2">Terminal pronto. Nenhum comando ainda.</div>`}</div><div class="tin"><span class="tp">${esc(T.prompt)}</span><input id="tcmd" autocomplete="off" autocapitalize="off" spellcheck="false" aria-label="Comando" placeholder="digite um comando e Enter"></div></div><p class="mu tkdica">💡 ${esc(T.dica)}</p>`;
if(!c.ran)return h+`<p class="mu">Rode pelo menos um comando para liberar a pergunta do diagnóstico.</p></div>`;
h+=tkMC("diag",3,"Diagnóstico",c.t.diag)+`</div>`;if(c.diag.pick!=null)h+=tkNext("Próximo: solução →");return h}
function tkAcao(){const c=TKC;let h=`<div class="card"><div class="q">4. Solução</div><p class="mu">Você já sabe a causa. Decida o que fazer: resolver no N1, escalar ou acionar a Segurança.</p>`+tkMC("acao",4,"Solução",c.t.acao)+`</div>`;if(c.acao.pick!=null)h+=tkNext("Próximo: nota do ticket →");return h}
function tkNota(){const c=TKC,N=c.t.nota;let h=`<div class="card"><div class="q">5. Nota do ticket</div><p class="mu">Escreva a nota de resolução, como no sistema de tickets: sintoma, o que verificou, a causa, o que fez e o resultado. Pode ser em português ou em inglês (em muitas empresas é em inglês).</p>`;
if(c.pts[4]==null)return h+`<textarea id="tknt" rows="8" placeholder="Sintoma:\nO que verifiquei:\nCausa:\nO que fiz:\nResultado:">${esc(c.nota.txt)}</textarea><p class="mu" id="tkntm" style="margin:6px 0 0">A correção procura ${N.itens.length} itens na sua nota.</p><div class="row"><button class="btn p" id="ntok">Registrar a nota</button></div></div>`;
h+=`<pre class="lg mine">${esc(c.nota.txt)}</pre><div class="sdchk">${N.itens.map((x,k)=>`<div class="${c.nota.hit[k]?"g":"r"}">${c.nota.hit[k]?"✅":"❌"} ${esc(x[0])}</div>`).join("")}</div><h3 style="margin:16px 0 6px;font-size:15px">Nota de referência</h3><pre class="lg">${esc(N.modelo)}</pre><div class="row"><button class="btn" id="ntcp">Copiar a nota de referência</button></div></div>`+tkNext("Ver o resultado →");return h}
function tkFim(){const c=TKC,t=c.t,tot=Math.round(c.pts.reduce((a,x)=>a+x,0)),ok=tot>=70;
if(!c.saved){c.saved=1;S.sd=S.sd||{};const o=S.sd[t.id]||{b:0,n:0};S.sd[t.id]={b:Math.max(o.b,tot),n:o.n+1,u:tot};markToday("sd");sdTick();save()}
const nx=TK.find(x=>x.id!=t.id&&!tkOk(x.id));
let h=`<div class="card ${ok?"win":"lose"}"><div class="q">${ok?"✅ Chamado resolvido":"↩️ Chamado reaberto"}: ${tot} de 100</div><p class="mu">${ok?"Bom atendimento. A nota fica salva no seu progresso.":"Abaixo de 70 o chamado volta para a fila. Releia as explicações e tente de novo."}</p><div class="sdbars">${TK_STEPS.map((s,k)=>`<div><span>${s}</span><span class="bar"><i style="width:${100*c.pts[k]/TK_W[k]}%"></i></span><b>${Math.round(c.pts[k])}/${TK_W[k]}</b></div>`).join("")}</div></div>`;
const tp=t.topicos.map(id=>TOP.find(x=>x.id==id)).filter(Boolean);if(tp.length)h+=`<div class="card"><div class="q">Para estudar este chamado</div><div class="tkchips">${tp.map(x=>`<a class="tkchip" href="#${x.id}">${x.ic} ${esc(x.n)}</a>`).join("")}</div></div>`;
h+=`<div class="row">${nx?`<button class="btn p" id="tkgo">Próximo chamado: ${esc(nx.id)} →</button>`:""}<button class="btn" id="tkre">Refazer este</button><button class="btn" id="tkq">Voltar à fila</button></div>`;
setTimeout(()=>{if($("tkgo"))$("tkgo").onclick=()=>tkStart(nx);$("tkre").onclick=()=>tkStart(t);$("tkq").onclick=()=>{TKC=null;rSd();window.scrollTo(0,0)}});return h}
function tkBind(){const c=TKC,el=$("v9"),t=c.t;
el.querySelectorAll(".pills[data-f] .pill").forEach(b=>b.onclick=()=>{c.tri[b.parentNode.dataset.f]=b.dataset.v;tkRender()});
if($("trok"))$("trok").onclick=()=>{const r=c.tri,T=t.triagem,n=(r.tipo==T.tipo)+[].concat(T.cat).includes(r.cat)+(+r.imp==T.impacto)+(+r.urg==T.urgencia);c.pts[0]=TK_W[0]*n/4;tkRender()};
el.querySelectorAll("input[data-q]").forEach(x=>x.onchange=()=>{const k=+x.dataset.q,A=c.ask;if(x.checked){if(A.sel.length<3)A.sel.push(k)}else A.sel=A.sel.filter(y=>y!=k);tkRender()});
if($("askok"))$("askok").onclick=()=>{const P=t.perguntas,good=Math.min(3,P.filter(q=>q.ok).length),g=c.ask.sel.filter(k=>P[k].ok).length;c.pts[1]=TK_W[1]*Math.min(1,g/good);tkRender()};
el.querySelectorAll("[data-run]").forEach(b=>b.onclick=()=>{tkRun(t.terminal.cmds[+b.dataset.run].c);tkRender();tkFocus()});
if($("tcmd"))$("tcmd").onkeydown=e=>{if(e.key=="Enter"){tkRun(e.target.value);tkRender();tkFocus()}};
el.querySelectorAll("[data-mc]").forEach(b=>b.onclick=()=>{const key=b.dataset.mc,X=c[key],k=+b.dataset.k;X.pick=k;c.pts[key=="diag"?2:3]=X.opts[k][1]?TK_W[key=="diag"?2:3]:0;tkRender()});
if($("tknt"))$("tknt").oninput=e=>{c.nota.txt=e.target.value};
if($("ntok"))$("ntok").onclick=()=>{const v=$("tknt").value.trim();if(v.length<30){$("tkntm").textContent="Escreva um pouco mais: pelo menos o que verificou, o que fez e o resultado.";return}
c.nota.txt=v;const low=v.toLowerCase();c.nota.hit=t.nota.itens.map(x=>new RegExp(x[1],"i").test(low));c.pts[4]=TK_W[4]*c.nota.hit.filter(Boolean).length/t.nota.itens.length;tkRender()};
if($("ntcp"))$("ntcp").onclick=async()=>{try{await navigator.clipboard.writeText(t.nota.modelo);$("ntcp").textContent="Copiada"}catch(e){}}}
function tkFocus(){const i=$("tcmd"),o=$("tout");if(o)o.scrollTop=o.scrollHeight;if(i)i.focus({preventScroll:true})}
sdTick();
