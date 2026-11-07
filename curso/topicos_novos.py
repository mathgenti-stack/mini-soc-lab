"""Tópicos novos do curso (estudar.html), escritos a partir do que as vagas de SOC júnior pedem.

Este arquivo é a fonte. `python curso/montar.py` grava estes tópicos e as perguntas de quiz em estudar.html.
Formato de cada tópico (igual aos que já existem na página):
  id    identificador (também usado em data/terminal/challenges.json, campo "roadmap")
  n     nome que aparece na tela
  ic    ícone
  tags  etiqueta das perguntas de quiz deste tópico (a primeira coluna de cada pergunta)
  st    o texto da aba Estudar (HTML simples: h3, p, ul/ol, table, pre)
  chk   o checklist ("Acertar X de Y no quiz..." é marcado sozinho pelo quiz;
        o item "Praticar no SOC Lab" é colocado pela página quando o tópico tem desafios)
"""

POWERSHELL = {
    "id": "powershell",
    "n": "PowerShell para Análise",
    "ic": "⚡",
    "tags": ["PowerShell"],
    "st": """<p class="mu">O PowerShell é a linha de comando moderna do Windows (também roda no Linux e no Mac). Para abrir: tecla Windows, digite <b>powershell</b> e Enter. Já existe no Windows, não precisa instalar.</p>
<h3>O que é, em uma frase</h3>
<p>No CMD tudo é <b>texto</b>. No PowerShell tudo é <b>objeto</b>: cada linha de um log vira uma ficha com campos (usuário, IP, horário), e você filtra pelos campos em vez de procurar palavras no texto.</p>
<h3>Comparação do dia a dia</h3>
<p>Pense numa planilha. O CMD te entrega a planilha impressa em papel: para achar algo, você lê linha por linha. O PowerShell te entrega a planilha no Excel: você filtra a coluna "IP", ordena a coluna "horário" e conta quantas linhas sobraram.</p>
<h3>Como os comandos funcionam</h3>
<ul>
<li>Os comandos se chamam <b>cmdlets</b> e têm o formato <b>Verbo-Substantivo</b>: Get-ChildItem (pegar os itens da pasta), Get-Content (pegar o conteúdo), Import-Csv (importar um CSV).</li>
<li>O <b>pipeline</b> <code>|</code> passa os objetos de um comando para o próximo, como uma esteira de fábrica.</li>
<li>Muitos comandos do Linux e do CMD funcionam como apelido: <b>ls</b>, <b>dir</b>, <b>cat</b>, <b>cd</b>.</li>
<li>Perdido? <b>Get-Help</b> Nome-Do-Comando explica o comando. <b>Get-Command</b> *event* procura comandos. <b>Get-Member</b> mostra os campos de um objeto.</li>
</ul>
<h3>Os 8 comandos que mais aparecem numa investigação</h3>
<table><tr><th>Comando</th><th>Para que serve</th></tr>
<tr><td>Get-Content arquivo.log</td><td>Ler um arquivo de texto (como o cat)</td></tr>
<tr><td>Select-String "Failed"</td><td>Procurar texto (como o grep)</td></tr>
<tr><td>Import-Csv logins.csv</td><td>Transformar cada linha do CSV em objeto</td></tr>
<tr><td>Where-Object</td><td>Filtrar: fica só o que bate com a condição</td></tr>
<tr><td>Select-Object</td><td>Escolher colunas, ou as primeiras linhas (-First 5)</td></tr>
<tr><td>Sort-Object</td><td>Ordenar (com -Descending, do maior para o menor)</td></tr>
<tr><td>Group-Object</td><td>Agrupar e contar: quantas vezes cada IP aparece</td></tr>
<tr><td>Measure-Object</td><td>Contar o total de linhas</td></tr>
</table>
<h3>Comparar valores</h3>
<p>No PowerShell não se usa = nem &gt; para comparar. Usa-se: <b>-eq</b> (igual), <b>-ne</b> (diferente), <b>-gt</b> (maior que), <b>-lt</b> (menor que), <b>-like</b> (parecido, com *) e <b>-match</b> (expressão regular).</p>
<h3>Exemplo prático: quem errou mais a senha?</h3>
<pre>Import-Csv logins.csv |
  Where-Object event_code -eq 4625 |
  Group-Object source_ip |
  Sort-Object Count -Descending |
  Select-Object -First 5 Name, Count</pre>
<p>Lendo em português: abra o CSV, fique só com os logins que falharam (4625), agrupe por IP, ordene do que mais falhou para o que menos falhou e mostre os 5 primeiros. Isso responde em segundos a pergunta mais comum de um ataque de força bruta.</p>
<h3>Logs do Windows direto no PowerShell</h3>
<ul>
<li><b>Get-WinEvent</b> lê o Visualizador de Eventos. Exemplo: <code>Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 20</code> traz os 20 últimos logins com falha.</li>
<li>Ler o log Security exige abrir o PowerShell <b>como administrador</b>.</li>
<li><b>ConvertFrom-Json</b> transforma JSON (logs de nuvem, como o Entra ID) em objetos.</li>
</ul>
<h3>No dia a dia de um SOC</h3>
<ul>
<li>Responder rápido: quantas falhas, de qual IP, contra quais contas, a que horas.</li>
<li>Coletar evidências de uma máquina: processos (Get-Process), conexões (Get-NetTCPConnection), serviços (Get-Service).</li>
<li><b>Os atacantes também usam PowerShell</b> (técnica T1059.001 do MITRE). Sinais suspeitos: <code>-EncodedCommand</code> (comando escondido em Base64), <code>-WindowStyle Hidden</code>, <code>IEX</code> baixando algo da internet.</li>
<li>O evento <b>4104</b> (log Microsoft-Windows-PowerShell/Operational) grava o código dos scripts que rodaram, quando o registro de script block está ligado. É ouro numa investigação.</li>
</ul>
<h3>Erros comuns</h3>
<ul>
<li>Usar = em vez de -eq dentro do Where-Object.</li>
<li>Esquecer as aspas em texto com espaço: "Failed password".</li>
<li>Achar que a "política de execução" (Execution Policy) é uma proteção de segurança. Ela só evita rodar scripts sem querer; um atacante desvia dela facilmente.</li>
</ul>
<h3>Pratique no lab</h3>
<p>No lab, aba <b>Terminal → PowerShell</b>, os desafios começam contando arquivos e terminam investigando um ataque com Get-WinEvent. Faça na ordem: cada um usa um comando novo.</p>
<h3>Como explicar numa entrevista</h3>
<p><b>Why is PowerShell useful for a SOC analyst?</b><br><i>It works with objects, so I can filter, group and count log events by field. For example, I can import a CSV of sign-ins, keep only event 4625 and group by source IP to find a brute-force source in a few seconds.</i></p>
<p><b>How can attackers abuse PowerShell, and how would you spot it?</b><br><i>They run encoded or hidden commands and download payloads into memory. I look for -EncodedCommand, hidden windows and downloads in process command lines, and I check event 4104 for the script content.</i></p>""",
    "chk": [
        "Explicar a diferença entre texto (CMD) e objetos (PowerShell)",
        "Usar o pipeline com Where-Object, Sort-Object e Select-Object",
        "Contar com Group-Object e Measure-Object",
        "Comparar com -eq, -ne, -gt, -like e -match",
        "Ler logs do Windows com Get-WinEvent e -FilterHashtable",
        "Achar ajuda com Get-Help, Get-Command e Get-Member",
        "Citar 3 sinais de PowerShell malicioso",
        "Acertar 8 de 10 no quiz de PowerShell",
    ],
}

LOGS = {
    "id": "logs",
    "n": "Logs e Eventos",
    "ic": "📜",
    "tags": ["Logs"],
    "st": """<h3>O que é um log</h3>
<p>Log é o <b>diário</b> de um sistema: cada linha diz o que aconteceu, quando, onde e com quem. Um login, um erro de senha, um programa que abriu, um arquivo apagado. Sem logs, o SOC fica cego: é neles que você descobre o que um atacante fez.</p>
<h3>Comparação do dia a dia</h3>
<p>É a câmera de segurança de um prédio, só que em texto. Ela não impede ninguém de entrar, mas mostra quem entrou, por qual porta e a que horas. O seu trabalho é assistir às gravações certas.</p>
<h3>As 5 perguntas que todo log responde</h3>
<ul><li><b>Quando?</b> data e hora (atenção ao fuso horário, normalmente UTC).</li><li><b>Onde?</b> qual máquina ou serviço.</li><li><b>Quem?</b> qual usuário ou conta.</li><li><b>De onde?</b> qual IP de origem.</li><li><b>O quê e o resultado?</b> login, falha, criação de conta, sucesso ou erro.</li></ul>
<h3>Windows: o Visualizador de Eventos</h3>
<p>Fica em Event Viewer (tecla Windows → "Visualizador de Eventos"). Os mais importantes estão em <b>Logs do Windows → Segurança</b>. Cada evento tem um número, o <b>Event ID</b>. Os que mais aparecem no SOC:</p>
<table><tr><th>Event ID</th><th>O que significa</th></tr>
<tr><td>4624</td><td>Login com sucesso</td></tr>
<tr><td>4625</td><td>Login com falha (senha errada ou usuário que não existe)</td></tr>
<tr><td>4634</td><td>Logoff (a pessoa saiu)</td></tr>
<tr><td>4672</td><td>Login de uma conta com privilégios de administrador</td></tr>
<tr><td>4688</td><td>Um programa (processo) foi iniciado</td></tr>
<tr><td>4720</td><td>Uma conta de usuário foi criada</td></tr>
<tr><td>4728 / 4732</td><td>Alguém foi colocado num grupo (por exemplo, administradores)</td></tr>
<tr><td>4740</td><td>Conta bloqueada por muitas senhas erradas</td></tr>
<tr><td>4767</td><td>Conta desbloqueada</td></tr>
<tr><td>1102</td><td>O log de segurança foi apagado (muito suspeito!)</td></tr>
</table>
<h3>Tipo de login (Logon Type)</h3>
<p>Os eventos 4624 e 4625 dizem <b>como</b> a pessoa tentou entrar: <b>2</b> = no teclado da máquina, <b>3</b> = pela rede (pasta compartilhada), <b>10</b> = Área de Trabalho Remota (RDP), <b>5</b> = serviço. Um tipo 10 vindo da internet às 3 da manhã chama atenção.</p>
<h3>Sysmon: o log com mais detalhes</h3>
<p>O Sysmon é uma ferramenta gratuita da Microsoft que registra muito mais coisa: <b>1</b> = processo criado (com a linha de comando completa), <b>3</b> = conexão de rede, <b>11</b> = arquivo criado, <b>22</b> = consulta DNS. Muitas empresas usam porque o log padrão do Windows não mostra tudo.</p>
<h3>Linux</h3>
<ul><li>Logins e sudo ficam em <b>/var/log/auth.log</b> (Ubuntu, Debian) ou <b>/var/log/secure</b> (Red Hat, CentOS).</li><li>Frases que importam: <b>Failed password</b> (senha errada), <b>Invalid user</b> (usuário que não existe), <b>Accepted password</b> (entrou), <b>sudo</b> (virou administrador para um comando).</li></ul>
<h3>Nuvem</h3>
<p>No Microsoft Entra ID (antigo Azure AD), os <b>sign-in logs</b> mostram cada login na nuvem, com país, aplicativo e um código de resultado (0 = sucesso; 50126 = usuário ou senha errados). Vêm em JSON.</p>
<h3>No dia a dia de um SOC</h3>
<ul><li><b>Força bruta:</b> muitos 4625 seguidos do mesmo IP.</li><li><b>Password spray:</b> poucas tentativas em muitas contas diferentes, do mesmo IP, para não bloquear ninguém.</li><li><b>Sucesso depois de muitas falhas:</b> um 4624 logo após vários 4625 = o atacante pode ter acertado.</li><li><b>Persistência:</b> conta nova (4720) colocada no grupo de administradores (4732) fora do horário.</li><li><b>Apagar rastros:</b> evento 1102 quase nunca é normal.</li></ul>
<h3>Erros comuns</h3>
<ul><li>Esquecer o fuso horário e montar a linha do tempo errada.</li><li>Olhar só as falhas e não ver o sucesso que veio depois.</li><li>Achar que "não tem log" significa "não aconteceu": às vezes o registro estava desligado.</li></ul>
<h3>Pratique no lab</h3>
<p>Os desafios da aba Praticar usam logs de verdade do lab: auth.log do Linux, um export do Visualizador de Eventos e o CSV de logins. Você vai contar 4625, achar o atacante e descobrir quem desbloqueou uma conta.</p>
<h3>Como explicar numa entrevista</h3>
<p><b>Which Windows event IDs do you know?</b><br><i>4624 is a successful logon and 4625 a failed one. 4740 means an account was locked out, 4720 a user was created, 4688 a process started and 1102 means the security log was cleared, which is very suspicious.</i></p>
<p><b>What is the difference between brute force and password spraying?</b><br><i>Brute force tries many passwords against one account. Password spraying tries a few common passwords against many accounts, so no single account gets locked.</i></p>""",
    "chk": [
        "Explicar o que é um log e as 5 perguntas que ele responde",
        "Saber de cor 4624, 4625, 4740 e 4720",
        "Explicar os tipos de login 2, 3 e 10",
        "Dizer para que serve o Sysmon",
        "Achar logins no Linux (auth.log ou secure)",
        "Diferenciar força bruta de password spray",
        "Acertar 8 de 10 no quiz de Logs",
    ],
}

SIEM = {
    "id": "siem",
    "n": "SIEM e Consultas (SPL e KQL)",
    "ic": "🔎",
    "tags": ["SIEM"],
    "st": """<h3>O que é um SIEM</h3>
<p>SIEM (Security Information and Event Management) é o sistema que <b>junta os logs de todas as máquinas num lugar só</b>, deixa você pesquisar neles e dispara alertas quando algo bate com uma regra. É a ferramenta principal do analista de SOC: é a primeira coisa que as vagas pedem.</p>
<h3>Comparação do dia a dia</h3>
<p>Imagine os logs de 5 mil computadores espalhados como cadernos em 5 mil gavetas. O SIEM recolhe todos os cadernos para uma biblioteca, organiza por data e cria um índice. Aí você pergunta "quem errou a senha mais de 20 vezes hoje?" e recebe a resposta em segundos.</p>
<h3>O que o SIEM faz</h3>
<ol><li><b>Coleta</b> os logs (Windows, Linux, firewall, nuvem, e-mail).</li><li><b>Normaliza</b>: dá o mesmo nome para o mesmo campo, venha de onde vier (ex.: o IP de origem sempre como src_ip).</li><li><b>Correlaciona</b>: liga eventos de fontes diferentes (falhas no VPN + login com sucesso + acesso a arquivos).</li><li><b>Alerta</b> quando uma regra é atendida.</li><li><b>Guarda</b> o histórico para investigar depois.</li></ol>
<h3>Os mais pedidos nas vagas</h3>
<ul><li><b>Splunk</b>, com a linguagem <b>SPL</b>.</li><li><b>Microsoft Sentinel</b>, com a linguagem <b>KQL</b> (a mesma do Defender XDR).</li><li>Também aparecem: IBM QRadar, Elastic (ELK) e Google SecOps.</li></ul>
<p>Aprenda bem um dos dois primeiros. A lógica é a mesma, só muda a escrita.</p>
<h3>A mesma pergunta nas duas linguagens</h3>
<p><b>"Quais IPs mais erraram a senha nas últimas 24 horas?"</b></p>
<p>Splunk (SPL):</p>
<pre>index=wineventlog EventCode=4625 earliest=-24h
| stats count by src_ip
| sort - count
| head 10</pre>
<p>Microsoft Sentinel (KQL):</p>
<pre>SecurityEvent
| where TimeGenerated &gt; ago(24h)
| where EventID == 4625
| summarize count() by IpAddress
| top 10 by count_</pre>
<p>Repare: as duas fazem <b>filtrar → agrupar e contar → ordenar → mostrar os primeiros</b>. É a mesma ideia do pipeline do PowerShell e do grep | sort | uniq -c do Linux. Quem entende um entende os outros.</p>
<h3>Dicionário rápido</h3>
<table><tr><th>Quero...</th><th>SPL</th><th>KQL</th></tr>
<tr><td>Filtrar</td><td>campo=valor ou | where</td><td>| where campo == valor</td></tr>
<tr><td>Contar por campo</td><td>| stats count by campo</td><td>| summarize count() by campo</td></tr>
<tr><td>Ordenar</td><td>| sort - count</td><td>| sort by count_ desc</td></tr>
<tr><td>Escolher colunas</td><td>| table a, b</td><td>| project a, b</td></tr>
<tr><td>Primeiros N</td><td>| head 10</td><td>| take 10 ou | top 10 by</td></tr>
<tr><td>Período</td><td>earliest=-24h</td><td>where TimeGenerated &gt; ago(24h)</td></tr>
</table>
<h3>Regras de detecção</h3>
<p>Um alerta nasce de uma <b>regra</b>: uma consulta que roda sozinha de tempos em tempos. Exemplo: "mais de 20 falhas do mesmo IP em 5 minutos". Regras boas pegam ataques sem gerar alertas demais. <b>Sigma</b> é um formato aberto para escrever regras uma vez e convertê-las para Splunk, Sentinel e outros.</p>
<h3>No dia a dia de um SOC</h3>
<ul><li>Chega um alerta: você abre no SIEM e pesquisa o que mais aquele IP ou usuário fez antes e depois.</li><li>Monta a <b>linha do tempo</b>: primeira falha, primeiro sucesso, o que fez depois de entrar.</li><li>Ajusta regras que geram falso positivo demais (ex.: ignorar o scanner de vulnerabilidades da própria empresa).</li></ul>
<h3>Erros comuns</h3>
<ul><li>Pesquisar sem limitar o período: a busca demora e traz lixo.</li><li>Confiar só no alerta e não olhar o contexto em volta.</li><li>Em KQL, usar = em vez de == para comparar.</li></ul>
<h3>Pratique no lab</h3>
<p>Os desafios desta aba fazem com grep, awk e PowerShell exatamente o que uma consulta de SIEM faz: filtrar, agrupar e contar no dataset de logins. No painel do lab, cada regra de detecção pode ser exportada como consulta SPL, KQL e Sigma: compare com o que você escreveu.</p>
<h3>Como explicar numa entrevista</h3>
<p><b>What is a SIEM and why does a SOC need one?</b><br><i>A SIEM collects and normalises logs from across the company, correlates them and raises alerts based on detection rules. Without it, analysts would have to search every system separately.</i></p>
<p><b>How would you find the top sources of failed logons?</b><br><i>In Splunk: filter EventCode 4625, then stats count by src_ip and sort descending. In Sentinel: SecurityEvent, where EventID == 4625, summarize count() by IpAddress and take the top 10.</i></p>""",
    "chk": [
        "Explicar o que é um SIEM e as 5 coisas que ele faz",
        "Citar Splunk (SPL) e Sentinel (KQL)",
        "Escrever a consulta de falhas por IP em SPL",
        "Escrever a mesma consulta em KQL",
        "Explicar como uma regra vira alerta",
        "Montar uma linha do tempo a partir dos logs",
        "Acertar 8 de 10 no quiz de SIEM",
    ],
}

PHISHING = {
    "id": "phishing",
    "n": "Análise de Phishing",
    "ic": "🎣",
    "tags": ["Phishing"],
    "st": """<h3>O que é phishing</h3>
<p>Phishing é um e-mail (ou SMS, ou mensagem) que <b>finge ser de alguém confiável</b> para fazer a pessoa clicar num link, abrir um anexo ou passar a senha. É a forma mais comum de ataque começar, e analisar e-mails suspeitos é tarefa diária do SOC Nível 1.</p>
<h3>Comparação do dia a dia</h3>
<p>É o golpista que liga dizendo ser do banco. A voz é educada e o assunto parece real, mas o número de telefone é estranho e ele tem pressa. No e-mail, o "número estranho" está nos <b>cabeçalhos</b>, e a pressa está no texto.</p>
<h3>Os tipos</h3>
<ul><li><b>Phishing comum:</b> enviado para muita gente ("sua conta será bloqueada").</li><li><b>Spear phishing:</b> feito sob medida para uma pessoa ou empresa.</li><li><b>BEC (Business Email Compromise):</b> finge ser o chefe ou um fornecedor pedindo pagamento ou troca de conta bancária. Muitas vezes nem tem link.</li><li><b>Smishing e vishing:</b> por SMS e por telefone.</li></ul>
<h3>Passo a passo da análise</h3>
<ol><li><b>Remetente:</b> o endereço do From bate com o nome? Domínio parecido é golpe: micros0ft.com, paypa1.com, empresa-suporte.com.</li><li><b>Reply-To e Return-Path:</b> se a resposta vai para outro endereço, desconfie.</li><li><b>Autenticação</b> (no cabeçalho Authentication-Results): <b>SPF</b> diz se o servidor que enviou pode mandar e-mail por aquele domínio; <b>DKIM</b> é uma assinatura que prova que o e-mail não foi alterado; <b>DMARC</b> diz o que fazer quando os dois falham. Falha em SPF ou DMARC num e-mail "do banco" é sinal forte de falsificação.</li><li><b>Received:</b> o caminho do e-mail, servidor por servidor. Lê-se <b>de baixo para cima</b>: o de baixo é a origem.</li><li><b>Links:</b> passe o mouse (sem clicar) e veja o endereço real. Analise em sites como urlscan.io ou VirusTotal.</li><li><b>Anexos:</b> nunca abra na sua máquina. Pegue o <b>hash</b> do arquivo e pesquise no VirusTotal, ou use uma sandbox (ex.: ANY.RUN).</li><li><b>Texto:</b> urgência, ameaça, prêmio, pedido de senha ou de pagamento.</li></ol>
<h3>Compartilhar com segurança (defang)</h3>
<p>Ao colocar um link perigoso num ticket, "desarme" para ninguém clicar sem querer: <code>hxxps://golpe[.]com/login</code>.</p>
<h3>O que fazer quando é phishing de verdade</h3>
<ul><li>Ver <b>quem mais recebeu</b> o mesmo e-mail e remover de todas as caixas.</li><li>Bloquear o remetente, o domínio e os links.</li><li>Descobrir se alguém <b>clicou ou digitou a senha</b>. Se sim: trocar a senha, encerrar as sessões e verificar o MFA e as regras de caixa de entrada criadas pelo atacante.</li><li>Registrar os IOCs (domínio, IP, hash, assunto) no ticket.</li></ul>
<h3>No dia a dia de um SOC</h3>
<p>Muitas empresas têm um botão "Reportar phishing" no Outlook. Cada e-mail reportado vira um caso para você decidir: <b>phishing</b>, <b>spam</b> (incômodo, mas não perigoso) ou <b>legítimo</b>. No MITRE ATT&amp;CK, phishing é a técnica <b>T1566</b>.</p>
<h3>Erros comuns</h3>
<ul><li>Clicar no link "só para ver".</li><li>Confiar no nome que aparece e não olhar o endereço real.</li><li>Achar que e-mail com SPF "pass" é seguro: o golpista pode ter o próprio domínio parecido, com SPF configurado.</li></ul>
<h3>Como explicar numa entrevista</h3>
<p><b>How do you analyse a reported phishing email?</b><br><i>I check the sender, reply-to and return-path, then the SPF, DKIM and DMARC results and the received headers. I inspect links and attachments safely with urlscan, VirusTotal or a sandbox. If it is malicious I find everyone who received it, remove it, block the indicators and check whether anyone clicked or entered credentials.</i></p>
<p><b>What are SPF, DKIM and DMARC?</b><br><i>SPF lists which servers may send mail for a domain, DKIM signs the message so changes can be detected, and DMARC tells receivers what to do when those checks fail.</i></p>""",
    "chk": [
        "Explicar phishing, spear phishing e BEC",
        "Checar From, Reply-To e Return-Path",
        "Explicar SPF, DKIM e DMARC em uma frase cada",
        "Analisar link e anexo sem clicar nem abrir",
        "Escrever um link no formato defang",
        "Dizer o que fazer se alguém digitou a senha",
        "Acertar 8 de 10 no quiz de Phishing",
    ],
}

IR = {
    "id": "ir",
    "n": "Triagem e Resposta a Incidentes",
    "ic": "🚨",
    "tags": ["IR"],
    "st": """<h3>O que é</h3>
<p><b>Triagem</b> é decidir, para cada alerta, se é real, quão grave é e o que fazer. <b>Resposta a incidentes</b> é o que vem depois, quando o alerta é real: parar o ataque, limpar e voltar ao normal. É o coração do trabalho do SOC.</p>
<h3>Comparação do dia a dia</h3>
<p>É a triagem de um pronto-socorro. Nem todo mundo que chega está grave: a enfermeira pergunta, mede a pressão e decide quem é atendido primeiro. O analista faz o mesmo com os alertas: confere, classifica e prioriza.</p>
<h3>Triagem em 5 perguntas</h3>
<ol><li><b>O que disparou?</b> Qual regra, qual máquina, qual usuário, que horário.</li><li><b>É normal para essa pessoa ou máquina?</b> Ela costuma logar daquele país? Aquele programa costuma rodar?</li><li><b>O que diz a inteligência de ameaças?</b> O IP, o domínio ou o hash já são conhecidos como maliciosos (VirusTotal, AbuseIPDB)?</li><li><b>Deu certo?</b> Houve login com sucesso, arquivo executado, dados enviados?</li><li><b>Qual o tamanho?</b> Uma máquina ou várias? Conta comum ou de administrador?</li></ol>
<h3>As classificações</h3>
<ul><li><b>Verdadeiro positivo:</b> ataque real. Responde e escala.</li><li><b>Falso positivo:</b> a regra errou, era atividade normal. Fecha e anota o porquê.</li><li><b>Verdadeiro positivo benigno:</b> aconteceu de verdade, mas é autorizado (ex.: um teste de invasão combinado).</li></ul>
<h3>Prioridade</h3>
<p>Mais urgente: conta de administrador, servidor importante, dados de clientes, ataque que <b>já funcionou</b> e ataque que está se espalhando. Menos urgente: tentativa bloqueada numa máquina isolada.</p>
<h3>As fases da resposta (NIST)</h3>
<ol><li><b>Preparação:</b> ferramentas, regras, contatos e treino prontos antes do ataque.</li><li><b>Detecção e análise:</b> o alerta e a investigação.</li><li><b>Contenção:</b> impedir que piore. Isolar a máquina na rede, desativar a conta, bloquear o IP.</li><li><b>Erradicação:</b> remover a ameaça (malware, contas criadas pelo atacante).</li><li><b>Recuperação:</b> voltar ao normal com segurança e vigiar.</li><li><b>Lições aprendidas:</b> o que melhorar para não acontecer de novo.</li></ol>
<h3>EDR: a ferramenta da máquina</h3>
<p>O EDR (Microsoft Defender for Endpoint, CrowdStrike, SentinelOne) vigia cada computador. Ele mostra a <b>árvore de processos</b> (que programa abriu qual), e com um clique <b>isola a máquina</b> da rede, mata um processo ou apaga um arquivo. Exemplo de árvore suspeita: o Word abrindo o PowerShell, que baixa algo da internet.</p>
<h3>MITRE ATT&amp;CK: dando nome ao ataque</h3>
<p>É um catálogo público de como os atacantes agem. <b>Táticas</b> são o objetivo (o "porquê": entrar, se manter, subir privilégio, roubar dados). <b>Técnicas</b> são o jeito (o "como"). Exemplos: T1566 Phishing, T1110 Força bruta, T1078 Uso de contas válidas, T1059.001 PowerShell, T1021.001 Área de Trabalho Remota. Citar a técnica no ticket ajuda todo mundo a entender rápido.</p>
<h3>IOCs e a pirâmide da dor</h3>
<p><b>IOC</b> (indicador de comprometimento) é uma pista concreta: hash de arquivo, IP, domínio. Bloquear um hash é fácil, mas o atacante troca o arquivo em segundos. Bloquear o <b>comportamento</b> (as técnicas) dói muito mais para ele. Essa é a ideia da "pirâmide da dor".</p>
<h3>Como escrever o ticket</h3>
<p>Um bom registro responde: <b>o que</b> aconteceu, <b>quando</b>, <b>onde</b> (máquina, usuário, IP), <b>o que você verificou</b>, <b>o que você fez</b> e <b>o que falta</b>. Escreva para alguém que vai ler às 3 da manhã sem contexto. Comunicação clara é a habilidade que mais aparece nas vagas.</p>
<h3>No dia a dia de um SOC</h3>
<ul><li>Os alertas chegam numa <b>fila</b>. Cada um tem um prazo de atendimento (SLA) conforme a gravidade.</li><li>O Nível 1 faz a triagem e resolve o simples. O que é grave ou complexo é <b>escalado</b> para o Nível 2 com tudo documentado.</li><li>Muitos SOCs trabalham em <b>turnos</b> (24 horas por dia). Na troca de turno, os casos abertos são passados com uma nota clara.</li><li>Para casos repetidos existem <b>playbooks</b>: o passo a passo combinado para cada tipo de alerta (phishing, força bruta, malware).</li></ul>
<h3>Erros comuns</h3>
<ul><li>Fechar um alerta como falso positivo sem anotar o motivo.</li><li>Agir antes de confirmar: bloquear a conta do diretor por um alerta que era viagem legítima.</li><li>Não olhar se o ataque <b>deu certo</b> (o sucesso depois das falhas).</li><li>Escalar sem contexto: "deu alerta, olhem aí" não ajuda ninguém.</li></ul>
<h3>Exemplo prático</h3>
<p>Alerta: login com sucesso na conta j.silva vindo de outro país, 2 minutos depois de 40 falhas do mesmo IP. Triagem: não é normal (ela trabalha em São Paulo), o IP está no AbuseIPDB, e o ataque deu certo. Classificação: verdadeiro positivo, prioridade alta, MITRE T1110 e T1078. Ação: desativar a sessão e a conta, bloquear o IP, verificar o que a conta acessou e escalar para o Nível 2 com tudo documentado.</p>
<h3>Pratique no lab</h3>
<p>Os desafios desta aba contam uma história: um password spray, o momento em que o atacante entrou e uma conta comprometida na nuvem. Depois, no <b>modo treinamento</b> do lab, você triagem alertas de verdade e recebe nota.</p>
<h3>Como explicar numa entrevista</h3>
<p><b>Walk me through how you triage an alert.</b><br><i>I check what triggered it and whether the activity is normal for that user or host. I enrich the indicators with threat intelligence, check whether the attack succeeded and how far it spread, then classify it, set the priority and either close it with a note or contain and escalate it.</i></p>
<p><b>What is MITRE ATT&amp;CK?</b><br><i>A public knowledge base of attacker tactics and techniques. Tactics are the goals, techniques are how they achieve them, for example T1110 brute force. I use it to describe what I see and to check detection coverage.</i></p>""",
    "chk": [
        "Fazer a triagem com as 5 perguntas",
        "Diferenciar verdadeiro positivo, falso positivo e benigno",
        "Dizer as fases da resposta a incidentes",
        "Explicar o que um EDR faz (árvore de processos e isolar)",
        "Explicar tática e técnica do MITRE ATT&CK com exemplos",
        "Explicar o que é um IOC e a pirâmide da dor",
        "Escrever um ticket com o quê, quando, onde e o que foi feito",
        "Acertar 8 de 10 no quiz de Resposta a Incidentes",
    ],
}

NEW_TOPICS = [POWERSHELL, LOGS, SIEM, PHISHING, IR]

# A trilha do curso: os módulos na ordem de estudo (substitui os módulos do TryHackMe na aba Tópicos).
TRILHA = [
    {"n": "Primeiros passos", "ic": "🚀", "ids": ["careers", "defsec", "offsec"],
     "d": "O que é cibersegurança, o que faz quem ataca, o que faz quem defende e onde o SOC entra."},
    {"n": "Como o computador funciona", "ic": "🖥️", "ids": ["insidepc", "ctypes", "clientserver", "virt", "cloud"],
     "d": "As peças, os tipos de máquina, quem pede e quem responde, máquinas virtuais e nuvem."},
    {"n": "Dados e codificação", "ic": "🔢", "ids": ["dados", "encoding"],
     "d": "Bits, bytes, hexadecimal, Base64: para não se assustar com um log 'embaralhado'."},
    {"n": "Sistemas operacionais", "ic": "🪟", "ids": ["so", "win", "segso", "ms"],
     "d": "Windows, contas, permissões e Active Directory: o terreno onde os ataques acontecem."},
    {"n": "Redes", "ic": "🌐", "ids": ["redes"],
     "d": "IP, DNS, portas e protocolos: como as máquinas conversam e por onde o ataque chega."},
    {"n": "Linha de comando", "ic": "⌨️", "ids": ["linux", "wcli", "powershell"],
     "d": "Bash, CMD e PowerShell para ler e filtrar logs. Tem desafios práticos no lab."},
    {"n": "O trabalho no SOC", "ic": "🛡️", "ids": ["soc", "logs", "siem", "phishing", "ir"],
     "d": "O dia a dia do analista: logs, SIEM, phishing e resposta a incidentes. O que as vagas mais pedem."},
]

# "Resumo de 1 minuto" de cada tópico novo (tela Recapitular).
RESUMOS = {
    "powershell": [
        "PowerShell trabalha com objetos (campos), não com texto: dá para filtrar por IP, usuário ou Event ID.",
        "Comandos são Verbo-Substantivo (Get-Content, Import-Csv) e o | passa objetos de um para o outro.",
        "Filtrar: Where-Object. Ordenar: Sort-Object. Contar por campo: Group-Object. Total: Measure-Object.",
        "Comparar com -eq, -ne, -gt, -lt, -like e -match (nunca com =).",
        "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} lê os logins com falha.",
        "Sinais de ataque: -EncodedCommand, janela escondida, IEX baixando da internet. O evento 4104 mostra o script.",
    ],
    "logs": [
        "Log é o diário do sistema: quando, onde, quem, de onde e o que aconteceu.",
        "4624 = login ok. 4625 = falha. 4740 = conta bloqueada. 4720 = conta criada. 4688 = programa iniciado. 1102 = log apagado.",
        "Logon Type: 2 = no teclado, 3 = pela rede, 10 = Área de Trabalho Remota (RDP).",
        "Sysmon dá mais detalhes: 1 = processo com linha de comando, 3 = conexão de rede, 22 = DNS.",
        "Linux: /var/log/auth.log (ou /var/log/secure). Procure Failed password, Invalid user, Accepted e sudo.",
        "Força bruta = muitas senhas numa conta. Spray = poucas senhas em muitas contas. Sucesso depois de falhas = alerta.",
    ],
    "siem": [
        "SIEM junta os logs de tudo, normaliza, correlaciona, alerta e guarda.",
        "Splunk usa SPL. Microsoft Sentinel usa KQL. A lógica é a mesma.",
        "Consulta típica: filtrar → contar por campo → ordenar → pegar os primeiros.",
        "SPL: stats count by src_ip | sort - count. KQL: summarize count() by IpAddress | top 10 by count_.",
        "Regra de detecção = consulta que roda sozinha e gera alerta. Sigma = regra em formato aberto.",
        "Sempre limite o período (earliest=-24h / ago(24h)).",
    ],
    "phishing": [
        "Phishing finge ser alguém confiável para roubar senha, dinheiro ou instalar malware (MITRE T1566).",
        "Spear phishing é sob medida. BEC finge ser o chefe ou um fornecedor pedindo pagamento.",
        "Cheque From, Reply-To e Return-Path. Domínio parecido (micros0ft.com) é golpe.",
        "SPF = servidor autorizado. DKIM = assinatura. DMARC = o que fazer se falhar.",
        "Received se lê de baixo para cima. Links e anexos: urlscan, VirusTotal ou sandbox, nunca clicar.",
        "Alguém digitou a senha? Trocar senha, encerrar sessões, checar MFA e regras da caixa de entrada.",
    ],
    "ir": [
        "Triagem: o que disparou, é normal, o que diz a threat intel, deu certo, qual o tamanho.",
        "Verdadeiro positivo, falso positivo e verdadeiro positivo benigno (autorizado).",
        "Fases: preparação, detecção e análise, contenção, erradicação, recuperação, lições aprendidas.",
        "EDR mostra a árvore de processos e isola a máquina. Word abrindo PowerShell = suspeito.",
        "MITRE ATT&CK: tática = porquê, técnica = como (T1110 força bruta, T1078 contas válidas).",
        "Ticket bom: o que, quando, onde, o que verificou, o que fez e o que falta.",
    ],
}
