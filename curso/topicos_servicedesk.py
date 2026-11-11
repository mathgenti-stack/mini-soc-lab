"""Fase 1 do curso: a fundação de Service Desk / IT Support.

Mesmo formato dos tópicos de topicos_novos.py (veja a explicação no topo daquele arquivo).
Os chamados para praticar ficam em curso/chamados.json; cada chamado diz a quais tópicos pertence.
"""

SD = {
    "id": "sd",
    "n": "O que é Service Desk",
    "ic": "🎧",
    "tags": ["ServiceDesk"],
    "st": """<p class="mu">Service Desk (ou IT Support, Help Desk) é a porta de entrada da maioria das pessoas que trabalham com TI. É também uma ótima base para o SOC: lá você aprende contas, redes, Windows, usuários e, principalmente, a registrar tudo num ticket.</p>
<h3>O que é, em uma frase</h3>
<p>O Service Desk é o <b>ponto único de contato</b> entre as pessoas da empresa e a TI. Quem tem um problema ou precisa de algo liga, manda um chat, um e-mail ou abre um chamado no portal, e o Service Desk registra, resolve ou encaminha.</p>
<h3>Comparação do dia a dia</h3>
<p>Pense no pronto-socorro de um hospital. Quem chega passa pela <b>triagem</b> (o quão grave é?), recebe uma <b>pulseira de prioridade</b>, e o caso simples é resolvido ali mesmo. O caso complicado vai para o especialista. Tudo fica no <b>prontuário</b>. No Service Desk, o prontuário é o ticket.</p>
<h3>Os níveis de suporte</h3>
<table><tr><th>Nível</th><th>Quem é</th><th>Exemplos</th></tr>
<tr><td>N0</td><td>Autoatendimento</td><td>Portal, base de conhecimento, troca de senha sozinho (SSPR)</td></tr>
<tr><td>N1</td><td>Primeiro atendimento: é aqui que você começa</td><td>Senha, conta bloqueada, Outlook, impressora, acesso, VPN</td></tr>
<tr><td>N2</td><td>Especialistas e suporte em campo</td><td>Redes, servidores, sistemas, troca de peça</td></tr>
<tr><td>N3</td><td>Engenharia ou fornecedor</td><td>Bug no sistema, mudança na arquitetura, suporte da Microsoft</td></tr></table>
<h3>Os 4 tipos de registro (ITIL)</h3>
<p>O ITIL é o conjunto de boas práticas que quase toda empresa usa para organizar a TI. Você não precisa decorar o livro, mas precisa saber estes 4:</p>
<ul>
<li><b>Incidente:</b> algo que funcionava parou ou piorou. Objetivo: <b>restaurar o serviço rápido</b>. Ex.: "o Outlook não abre".</li>
<li><b>Requisição de serviço:</b> um pedido de algo padrão, que não está quebrado. Normalmente precisa de <b>aprovação</b>. Ex.: "preciso de acesso à pasta do RH", "quero instalar o Visio".</li>
<li><b>Problema:</b> a <b>causa raiz</b> por trás de incidentes repetidos. Ex.: 30 chamados de VPN caindo toda segunda-feira.</li>
<li><b>Mudança:</b> uma alteração planejada no ambiente, com aprovação e janela de horário. Ex.: atualizar o firewall no sábado à noite.</li>
</ul>
<h3>O ciclo de vida de um ticket</h3>
<p><b>Novo</b> → <b>Atribuído</b> → <b>Em andamento</b> → <b>Aguardando</b> (o usuário ou um fornecedor; o relógio do SLA costuma pausar) → <b>Resolvido</b> → <b>Fechado</b> (depois que o usuário confirma, ou depois de alguns dias sem resposta).</p>
<h3>Prioridade = impacto × urgência</h3>
<p><b>Impacto</b> é quantas pessoas ou quanto do negócio é afetado. <b>Urgência</b> é quanto tempo dá para esperar. Juntando os dois:</p>
<table><tr><th></th><th>Urgência alta (parou)</th><th>Urgência média</th><th>Urgência baixa (dá para esperar)</th></tr>
<tr><td><b>Impacto alto</b> (empresa ou serviço crítico)</td><td>P1 Crítica</td><td>P2 Alta</td><td>P3 Média</td></tr>
<tr><td><b>Impacto médio</b> (um setor, um grupo)</td><td>P2 Alta</td><td>P3 Média</td><td>P4 Baixa</td></tr>
<tr><td><b>Impacto baixo</b> (uma pessoa)</td><td>P3 Média</td><td>P4 Baixa</td><td>P4 Baixa</td></tr></table>
<p>Cada empresa tem a sua tabela, mas a lógica é sempre essa. Uma pessoa sem conseguir trabalhar é P3. O sistema de vendas fora do ar para todos é P1.</p>
<h3>SLA: o prazo combinado</h3>
<p>SLA (Service Level Agreement) é o acordo de tempo de <b>primeira resposta</b> e de <b>solução</b> para cada prioridade. Exemplo comum: P1 = resposta em 15 min e solução em 4 h; P4 = resposta em 1 dia útil e solução em 5 dias. Estourar o SLA aparece nos relatórios, por isso você acompanha a fila o tempo todo.</p>
<h3>Escalar: quando e como</h3>
<ul>
<li><b>Escalonamento funcional:</b> passar para quem sabe ou tem acesso (N2 de Redes, time de Sistemas). Faça quando a solução está fora do seu conhecimento, do seu acesso ou do tempo do SLA.</li>
<li><b>Escalonamento hierárquico:</b> avisar o coordenador. Faça quando o impacto é grande, o SLA vai estourar ou o usuário é crítico para o negócio.</li>
<li><b>Segurança:</b> phishing com senha digitada, malware, notebook perdido, pedido suspeito de reset. <b>Sempre</b> avise a Segurança (o SOC), mesmo que pareça pequeno.</li>
<li>Escalar bem é deixar o ticket pronto: o que acontece, desde quando, quem é afetado, o que você já testou e o resultado. Ninguém deve precisar ligar para o usuário de novo para perguntar o básico.</li>
</ul>
<h3>Métricas que você vai ouvir</h3>
<ul>
<li><b>FCR</b> (First Contact Resolution): resolvido no primeiro contato, sem escalar.</li>
<li><b>MTTR</b>: tempo médio até resolver.</li>
<li><b>CSAT</b>: nota de satisfação que o usuário dá depois.</li>
<li><b>Backlog</b>: quantos chamados abertos estão parados na fila.</li>
</ul>
<h3>Ferramentas</h3>
<p>Sistemas de ticket: <b>ServiceNow</b>, <b>Jira Service Management</b>, Freshservice, Zendesk, TOPdesk. Acesso remoto: Quick Assist, TeamViewer, AnyDesk, ScreenConnect (sempre com a permissão do usuário). Administração: Active Directory, Microsoft 365 admin center, Entra ID, Intune. A <b>base de conhecimento</b> (KB) é sua melhor amiga: procure antes de resolver e escreva um artigo depois de resolver algo novo.</p>
<h3>No dia a dia de um Service Desk</h3>
<ul>
<li>Você começa o turno olhando a fila: o que está perto de estourar o SLA, o que voltou do usuário, o que é P1.</li>
<li>Atende telefone, chat e e-mail, e registra <b>tudo</b> como ticket, até o que resolveu em 2 minutos.</li>
<li>Os campeões de volume: senha e conta bloqueada, MFA, Outlook e Teams, impressora, VPN, acesso a pastas e sistemas, computador lento, novo funcionário.</li>
<li>Muita coisa de segurança chega primeiro no Service Desk: "recebi um e-mail estranho", "meu computador abriu uma janela pedindo resgate", "alguém ligou dizendo que era da TI".</li>
</ul>
<h3>Do Service Desk ao SOC</h3>
<p>O analista de SOC lê eventos de conta bloqueada, reset de senha e login fora do normal. No Service Desk você vê o outro lado: <b>por que</b> a conta bloqueou (um celular com a senha antiga), como funciona o MFA, como um usuário cai num phishing. Quem passou pelo suporte entende os alertas muito mais rápido. Por isso esta fase vem primeiro.</p>
<h3>Pratique</h3>
<p>Na <b>Fila de chamados</b> (menu Chamados) você atende chamados completos: triagem, perguntas ao usuário, diagnóstico com comandos, solução e nota no ticket.</p>
<h3>Erros comuns</h3>
<ul>
<li>Resolver por telefone e não registrar o ticket: o trabalho some das métricas e ninguém aprende com ele.</li>
<li>Tratar requisição como incidente (ou o contrário). Pedido de acesso não é algo quebrado: precisa de aprovação.</li>
<li>Dar prioridade pelo tom do usuário, e não pelo impacto e pela urgência.</li>
<li>Fechar o ticket sem confirmar com o usuário que funcionou.</li>
<li>Escalar com "não funciona" e nada mais.</li>
</ul>
<h3>Como explicar numa entrevista</h3>
<p><b>What is the difference between an incident and a service request?</b><br><i>An incident is something that stopped working or got worse, and the goal is to restore the service quickly. A service request is a standard request for something new, like access or software, and it usually needs approval.</i></p>
<p><b>How do you prioritise your tickets?</b><br><i>By impact and urgency, not by who shouts loudest. A whole department unable to work comes before one user with a cosmetic issue. Then I keep an eye on SLA times, so nothing sits in the queue until it breaches.</i></p>""",
    "chk": [
        "Explicar o que é o Service Desk e os níveis N0 a N3",
        "Diferenciar incidente, requisição, problema e mudança",
        "Calcular a prioridade com impacto e urgência",
        "Explicar o que é SLA e o ciclo de vida de um ticket",
        "Dizer quando e como escalar um chamado",
        "Acertar 8 de 10 no quiz de Service Desk",
    ],
}

ATEND = {
    "id": "atend",
    "n": "Atendimento ao Usuário",
    "ic": "💬",
    "tags": ["Atendimento"],
    "st": """<p class="mu">No Service Desk, saber tecnologia é metade do trabalho. A outra metade é falar com pessoas: entender o que elas querem dizer, acalmar quem está nervoso, confirmar quem é quem e escrever de forma que outra pessoa entenda.</p>
<h3>O que é, em uma frase</h3>
<p>Bom atendimento é <b>entender o problema certo, com a pessoa certa, e deixar claro o que vai acontecer</b>, sem jargão e sem prometer o que não depende de você.</p>
<h3>Comparação do dia a dia</h3>
<p>Pense num bom médico de família. Ele deixa você falar, faz perguntas para entender ("dói quando?", "desde quando?"), explica em palavras simples, diz o que vai fazer e quando volta a falar com você. E anota tudo no prontuário.</p>
<h3>O roteiro de um atendimento</h3>
<ol>
<li><b>Abertura:</b> cumprimente, diga seu nome e o setor. "Bom dia, Service Desk, aqui é a Júlia."</li>
<li><b>Identificação:</b> nome, setor, ramal ou e-mail. Antes de mexer em senha ou MFA, <b>confirme a identidade</b> pelo processo da empresa.</li>
<li><b>Entender:</b> deixe a pessoa explicar, depois pergunte: o que aparece na tela, desde quando, o que mudou, só com você ou com outros.</li>
<li><b>Registrar:</b> abra o ticket enquanto conversa.</li>
<li><b>Resolver ou encaminhar:</b> e diga qual é o próximo passo e o prazo.</li>
<li><b>Confirmar e encerrar:</b> peça para a pessoa testar, passe o número do chamado e pergunte se há mais alguma coisa.</li>
</ol>
<h3>Perguntas abertas e fechadas</h3>
<ul>
<li><b>Abertas</b> fazem a pessoa contar: "O que acontece quando você tenta entrar?" Use no começo.</li>
<li><b>Fechadas</b> confirmam um detalhe: "Aparece a palavra bloqueada?" (sim ou não). Use para fechar o diagnóstico.</li>
<li><b>Parafrasear</b> evita mal-entendidos: "Então, desde ontem o Outlook abre mas não chegam e-mails novos, certo?"</li>
</ul>
<h3>Verificar a identidade (e não cair em golpe)</h3>
<p>Golpistas ligam para o Service Desk fingindo ser um funcionário (ou o diretor!) para pedir reset de senha ou de MFA. Isso se chama <b>engenharia social</b> por telefone (vishing). Sinais: muita <b>urgência</b>, uso de <b>autoridade</b> ("sou o diretor, resolve agora"), pedido para mandar o código para <b>outro número</b> ou e-mail pessoal.</p>
<ul>
<li>Siga o processo: ligar de volta no número <b>cadastrado</b>, confirmar com o gestor, perguntas de verificação, ou verificação pelo Teams com vídeo.</li>
<li><b>Nunca peça a senha</b> do usuário. Ninguém da TI precisa dela.</li>
<li>Pedido suspeito? Recuse com educação, registre e avise a Segurança.</li>
</ul>
<h3>Usuário irritado</h3>
<ul>
<li><b>Ouça</b> até o fim, sem interromper.</li>
<li><b>Reconheça</b> o impacto: "Entendo, você tem uma apresentação daqui a pouco e isso atrapalha muito."</li>
<li><b>Peça desculpas pela situação</b> (não precisa assumir culpa) e <b>foque na solução</b>: "Vamos resolver juntos. Primeiro, me diga..."</li>
<li>Dê um prazo realista e cumpra. Se não sabe, diga quando vai dar notícia.</li>
<li>Nunca discuta, nunca culpe o usuário ("você deve ter feito algo errado").</li>
</ul>
<h3>Escrever no ticket</h3>
<p>Quase todo sistema tem dois campos: a <b>nota interna</b> (work notes: só a TI vê) e o <b>comentário para o usuário</b> (ele recebe por e-mail). Uma boa nota diz:</p>
<ul><li>O sintoma, com a mensagem de erro exata.</li><li>O que você verificou e o que encontrou.</li><li>O que você fez.</li><li>O resultado (testado com o usuário?).</li><li>O próximo passo, se houver.</li></ul>
<pre>User reported: "account locked" when signing in to PC-FIN-07.
Verified identity via callback to registered number.
Get-ADUser: LockedOut=True, BadLogonCount=5. Unlocked account.
Cause: old password saved on phone mail app; user updated it.
Tested: user signed in successfully. Resolved.</pre>
<p>Em muitas vagas (e em empresas internacionais) a nota é em inglês. Frases curtas e no passado bastam.</p>
<h3>Frases úteis em inglês</h3>
<ul>
<li>"Could you tell me exactly what error message you see?"</li>
<li>"Has anything changed since it last worked?"</li>
<li>"I'm going to connect to your computer remotely. Is that OK?"</li>
<li>"I'll escalate this to our network team. You'll get an update within four hours."</li>
<li>"Could you try it now and let me know if it works?"</li>
</ul>
<h3>Acesso remoto com respeito</h3>
<p>Peça permissão antes de conectar, diga o que vai fazer, não abra arquivos pessoais e avise quando terminar. Se precisar ver algo sensível (e-mail, planilha de salário), peça para a pessoa mostrar.</p>
<h3>No dia a dia de um Service Desk</h3>
<ul>
<li>Você atende dezenas de pessoas por dia, com níveis de conhecimento muito diferentes: adapte a linguagem.</li>
<li>Chat e e-mail exigem texto claro, com passos numerados.</li>
<li>Muitos tickets voltam porque o usuário não entendeu a resposta. Confirmar antes de fechar evita reabertura.</li>
<li>Um usuário bem atendido reporta mais rápido o e-mail estranho, e isso ajuda a Segurança.</li>
</ul>
<h3>Pratique</h3>
<p>Na <b>Fila de chamados</b>, a etapa "Perguntas ao usuário" treina exatamente isso: escolher as perguntas que resolvem o caso. A etapa final pede a nota do ticket.</p>
<h3>Erros comuns</h3>
<ul>
<li>Usar jargão: "seu DHCP não está entregando lease" em vez de "seu computador não recebeu endereço da rede".</li>
<li>Prometer prazo que depende de outro time.</li>
<li>Resetar senha ou MFA sem confirmar a identidade.</li>
<li>Escrever opinião no ticket ("usuário difícil"). O ticket é um documento da empresa.</li>
<li>Fechar sem testar com o usuário.</li>
</ul>
<h3>Como explicar numa entrevista</h3>
<p><b>How would you handle an angry user?</b><br><i>I let them explain without interrupting, acknowledge the impact on their work and apologise for the situation. Then I focus on what I can do now, give a realistic timeframe and keep them updated, even if the fix depends on another team.</i></p>
<p><b>A caller says he is a director and needs his password reset right now. What do you do?</b><br><i>I follow the identity verification process anyway, for example a callback to the number on file or confirmation from his manager. Urgency and authority are classic social engineering tricks. If anything looks wrong, I refuse politely, log it and inform the security team.</i></p>""",
    "chk": [
        "Seguir o roteiro: abertura, identificação, entender, registrar, resolver, confirmar",
        "Usar perguntas abertas, fechadas e parafrasear",
        "Verificar a identidade antes de resetar senha ou MFA",
        "Reconhecer sinais de engenharia social por telefone",
        "Lidar com um usuário irritado sem discutir",
        "Escrever uma nota de ticket clara (de preferência em inglês)",
        "Acertar 8 de 10 no quiz de Atendimento",
    ],
}

TROUBLE = {
    "id": "trouble",
    "n": "Troubleshooting na Prática",
    "ic": "🔍",
    "tags": ["Troubleshooting"],
    "st": """<p class="mu">Troubleshooting é o jeito organizado de achar a causa de um problema. É o que separa o técnico que "tenta coisas" do que resolve. E é a mesma lógica que o analista de SOC usa numa investigação.</p>
<h3>O que é, em uma frase</h3>
<p>É <b>investigar antes de mexer</b>: entender o sintoma, levantar hipóteses da mais simples para a mais complexa, testar uma de cada vez e registrar o que funcionou.</p>
<h3>Comparação do dia a dia</h3>
<p>A luz da sala não acende. Você não chama um eletricista para trocar a fiação. Primeiro olha: a lâmpada queimou? Só essa sala está sem luz ou a casa toda? O disjuntor caiu? Do mais simples para o mais complexo, uma coisa de cada vez.</p>
<h3>O método em 7 passos (CompTIA A+)</h3>
<ol>
<li><b>Identificar o problema:</b> perguntar, ver o erro, descobrir o que mudou, reproduzir.</li>
<li><b>Criar uma teoria</b> da causa provável, começando pelo óbvio.</li>
<li><b>Testar a teoria.</b> Errou? Volte ao passo 2 ou escale.</li>
<li><b>Planejar a solução</b> e pensar no efeito dela (vai afetar outras pessoas?).</li>
<li><b>Aplicar a solução</b> ou escalar.</li>
<li><b>Verificar</b> que tudo funciona e, se der, prevenir que volte.</li>
<li><b>Documentar</b> causa, solução e resultado.</li>
</ol>
<h3>As perguntas que dividem o problema</h3>
<ul>
<li><b>Quem?</b> Só uma pessoa, um setor ou todo mundo? Só uma pessoa = olhe a máquina ou a conta dela. Todos = olhe o servidor, a rede ou o serviço.</li>
<li><b>O quê?</b> Um aplicativo ou tudo? Um site ou toda a internet?</li>
<li><b>Quando?</b> Desde quando? Sempre ou às vezes? Depois de uma atualização, de trocar a senha, de mudar de sala?</li>
<li><b>Onde?</b> No escritório e em casa? No Wi-Fi e no cabo?</li>
</ul>
<h3>Rede: de baixo para cima</h3>
<ol>
<li><b>Físico:</b> cabo conectado? Luz da placa acesa? Wi-Fi ligado, modo avião desligado?</li>
<li><b>Endereço IP:</b> <code>ipconfig</code>. IP <b>169.254.x.x</b> significa que o computador não recebeu endereço do DHCP (problema de cabo, porta, switch ou DHCP).</li>
<li><b>Gateway:</b> <code>ping</code> no gateway (o roteador). Respondeu? A rede local está ok.</li>
<li><b>Internet:</b> <code>ping 8.8.8.8</code>. Respondeu? A saída para a internet funciona.</li>
<li><b>DNS:</b> <code>nslookup site</code>. O ping no IP funciona, mas o nome não abre? É DNS.</li>
<li><b>Aplicação:</b> <code>Test-NetConnection servidor -Port 443</code> testa a porta do serviço.</li>
</ol>
<h3>Comandos que você vai usar toda semana</h3>
<table><tr><th>Comando</th><th>Para que serve</th></tr>
<tr><td>ipconfig /all</td><td>IP, gateway, DNS, DHCP, endereço MAC</td></tr>
<tr><td>ipconfig /release e /renew</td><td>Devolver e pedir um IP novo ao DHCP</td></tr>
<tr><td>ipconfig /flushdns</td><td>Limpar o cache de DNS do computador</td></tr>
<tr><td>ping e tracert</td><td>Testar se um destino responde e ver o caminho até ele</td></tr>
<tr><td>nslookup nome</td><td>Perguntar ao DNS qual o IP de um nome</td></tr>
<tr><td>gpupdate /force e gpresult /r</td><td>Atualizar as políticas (GPO) e ver quais estão aplicadas</td></tr>
<tr><td>whoami /groups</td><td>Ver os grupos da conta logada</td></tr>
<tr><td>sfc /scannow</td><td>Verificar e corrigir arquivos do Windows</td></tr>
<tr><td>Get-Service e Restart-Service</td><td>Ver e reiniciar serviços (ex.: Spooler, da impressão)</td></tr>
<tr><td>taskmgr, resmon, eventvwr</td><td>Gerenciador de Tarefas, Monitor de Recursos, Visualizador de Eventos</td></tr>
</table>
<h3>Casos clássicos e o primeiro teste</h3>
<ul>
<li><b>Sem internet:</b> ipconfig. 169.254? Cabo, porta ou DHCP. IP normal? ping no gateway e depois nslookup.</li>
<li><b>Computador lento:</b> Gerenciador de Tarefas (CPU, memória, disco) e espaço livre no disco C:.</li>
<li><b>Impressora:</b> fila travada? Limpar a fila e reiniciar o serviço Spooler. Só um setor? Olhe o driver ou a impressora.</li>
<li><b>Outlook:</b> funciona no navegador (Outlook na web)? Sim = problema no computador (perfil, cache). Não = conta, licença ou serviço.</li>
<li><b>Site interno não abre:</b> nslookup do nome. DNS errado (ex.: 8.8.8.8 configurado à mão) não conhece os nomes internos.</li>
<li><b>VPN:</b> internet funciona? Senha e MFA ok? A hora do computador está certa? Outras pessoas conseguem?</li>
</ul>
<h3>No dia a dia de um Service Desk</h3>
<ul>
<li>Reiniciar resolve muita coisa, mas se o problema volta, a causa continua lá: registre e procure o porquê.</li>
<li>Antes de mudar algo, anote como estava. Se piorar, você sabe voltar.</li>
<li>Se o mesmo problema aparece em vários tickets, avise o coordenador: pode ser um <b>Problema</b> (causa raiz) ou um incidente grave começando.</li>
<li>Muitos sintomas de segurança aparecem como "lentidão" ou "janela estranha": processo desconhecido usando CPU, programa novo que ninguém instalou. Na dúvida, escale para a Segurança.</li>
</ul>
<h3>Pratique</h3>
<p>Na <b>Fila de chamados</b>, cada chamado tem um terminal de diagnóstico: rode ipconfig, ping, nslookup, Get-ADUser e outros, e descubra a causa pela saída dos comandos.</p>
<h3>Erros comuns</h3>
<ul>
<li>Mudar três coisas ao mesmo tempo: se funcionar, você não sabe qual resolveu.</li>
<li>Pular a pergunta "o que mudou?". Quase sempre algo mudou.</li>
<li>Reinstalar ou formatar logo de cara.</li>
<li>Não confirmar com o usuário que voltou a funcionar.</li>
<li>Não documentar a solução, e alguém perder uma hora com o mesmo problema amanhã.</li>
</ul>
<h3>Como explicar numa entrevista</h3>
<p><b>A user says they can't access the internet. Walk me through it.</b><br><i>First I check if it's only them or others too. Then I go bottom-up: cable or Wi-Fi, then ipconfig. A 169.254 address means no DHCP lease. If the IP is fine, I ping the gateway, then an external IP, then use nslookup to test DNS. That tells me which layer is broken before I change anything.</i></p>
<p><b>What do you do if you can't fix an issue?</b><br><i>I escalate it to the right team with everything I found: symptoms, what I tested and the results, so they don't have to start again. And I tell the user who has it now and when they'll hear back.</i></p>""",
    "chk": [
        "Seguir os 7 passos do método de troubleshooting",
        "Dividir o problema com quem, o quê, quando e onde",
        "Diagnosticar rede de baixo para cima (cabo, IP, gateway, internet, DNS)",
        "Explicar o que significa um IP 169.254.x.x",
        "Usar ipconfig, ping, nslookup, gpupdate e gpresult",
        "Resolver os casos clássicos: lento, impressora, Outlook, VPN",
        "Acertar 8 de 10 no quiz de Troubleshooting",
    ],
}

CONTAS = {
    "id": "contas",
    "n": "Contas, Acessos e Microsoft 365",
    "ic": "🔑",
    "tags": ["Contas"],
    "st": """<p class="mu">Contas e acessos são o tipo de chamado mais comum no Service Desk e, ao mesmo tempo, o maior alvo dos atacantes. Este tópico mostra o trabalho do dia a dia. O tópico Administração Microsoft (no módulo Sistemas operacionais) explica o Active Directory por dentro.</p>
<h3>O que é, em uma frase</h3>
<p>Cuidar de contas é garantir que <b>cada pessoa tenha o acesso que precisa, e só ele</b>: criar, desbloquear, resetar, dar e tirar acessos, sempre com aprovação e registro.</p>
<h3>Comparação do dia a dia</h3>
<p>Pense na portaria de um prédio comercial. Cada funcionário recebe um crachá que abre só os andares do setor dele. Quem muda de setor troca de crachá (e devolve o antigo). Quem sai devolve o crachá no último dia. E ninguém empresta o crachá.</p>
<h3>Onde as contas moram</h3>
<ul>
<li><b>Active Directory (AD):</b> as contas da rede local da empresa (login no Windows, pastas, impressoras). Ferramenta: <b>ADUC</b> (dsa.msc) ou PowerShell.</li>
<li><b>Entra ID</b> (antigo Azure AD): as contas na nuvem da Microsoft (e-mail, Teams, OneDrive). Ferramenta: <b>Microsoft 365 admin center</b> e portal do Entra.</li>
<li>Na maioria das empresas é <b>híbrido</b>: a conta nasce no AD e é copiada para o Entra ID pelo Entra Connect. Por isso, às vezes a mudança "demora" uns minutos para aparecer na nuvem.</li>
</ul>
<h3>Bloqueada, desativada, expirada: não confunda</h3>
<table><tr><th>Estado</th><th>O que é</th><th>O que fazer</th></tr>
<tr><td>Bloqueada (locked out)</td><td>Errou a senha várias vezes; trava por segurança</td><td>Desbloquear (Unlock) e achar a causa</td></tr>
<tr><td>Senha expirada</td><td>A senha passou do prazo da política</td><td>Usuário troca a senha (ou reset com troca no próximo login)</td></tr>
<tr><td>Desativada (disabled)</td><td>Alguém desligou a conta de propósito (desligamento, afastamento)</td><td>Não reative sem pedido aprovado do RH ou do gestor</td></tr>
<tr><td>Conta expirada</td><td>Conta com data de fim (estagiário, terceiro)</td><td>Só estende com aprovação</td></tr></table>
<h3>Conta que bloqueia toda hora</h3>
<p>A pessoa trocou a senha, mas algum aparelho ou programa continua tentando a senha <b>antiga</b>: o e-mail no celular, um drive de rede mapeado com senha salva, uma sessão de Área de Trabalho Remota esquecida. A cada tentativa, um erro, até bloquear. No controlador de domínio, o evento <b>4740</b> mostra o <b>Caller Computer Name</b>: de onde vieram as tentativas. (É o mesmo evento que o SOC usa para detectar força bruta.)</p>
<h3>Comandos do dia a dia</h3>
<pre>Get-ADUser ana.souza -Properties LockedOut,BadLogonCount,PasswordLastSet,PasswordExpired,Enabled
Unlock-ADAccount ana.souza
Set-ADAccountPassword ana.souza -Reset          # e marcar "trocar no próximo login"
Get-ADPrincipalGroupMembership ana.souza | Select-Object Name
Add-ADGroupMember "GG-RH-Leitura" -Members carla.lima
net user ana.souza /domain                      # a versão do CMD</pre>
<h3>MFA e troca de senha</h3>
<ul>
<li><b>MFA</b> (autenticação em vários fatores): senha + algo que você tem (app Authenticator, chave de segurança) ou é.</li>
<li>Celular novo, app apagado: o Service Desk <b>confirma a identidade</b> e redefine os métodos de MFA ("require re-register MFA"). No próximo login a pessoa cadastra o celular novo.</li>
<li>Recebeu notificação de MFA que não pediu? Alguém tem a senha dela. <b>Não é chamado comum: é caso de segurança</b> (fadiga de MFA). Troca de senha, revogar sessões e avisar o SOC.</li>
<li><b>SSPR</b> (Self-Service Password Reset): o próprio usuário troca a senha pelo portal, com MFA. Menos chamados e menos risco.</li>
</ul>
<h3>Microsoft 365 no Service Desk</h3>
<ul>
<li><b>Licença:</b> sem licença com Exchange, não há caixa de e-mail. Conta nova que "não tem e-mail" quase sempre é licença.</li>
<li><b>Caixa compartilhada</b> (financeiro@, suporte@): várias pessoas leem a mesma caixa. Permissões: <b>Full Access</b> (abrir), <b>Send As</b> (enviar como a caixa), <b>Send on Behalf</b> (enviar "em nome de").</li>
<li><b>Caixa cheia:</b> o limite depende da licença (50 GB ou 100 GB é comum). Arquivamento online e limpeza resolvem.</li>
<li><b>Grupos:</b> lista de distribuição (só e-mail), grupo do Microsoft 365 (e-mail + Teams + SharePoint) e grupo de segurança (dá permissão).</li>
<li><b>OneDrive, SharePoint e Teams:</b> pedidos de acesso a sites vão para o <b>dono do site</b> aprovar.</li>
<li><b>Intune:</b> gerencia notebooks e celulares da empresa: instalar apps, aplicar regras, bloquear e apagar à distância um aparelho perdido.</li>
</ul>
<h3>Entrou, mudou, saiu (Joiners, Movers, Leavers)</h3>
<ul>
<li><b>Entrou:</b> conta na OU certa, grupos do cargo, licença, equipamento, tudo pedido pelo RH ou gestor.</li>
<li><b>Mudou de setor:</b> dar os acessos novos <b>e tirar os antigos</b>. Quem acumula acessos de todos os setores por onde passou é um risco enorme.</li>
<li><b>Saiu:</b> desativar a conta na hora combinada, revogar sessões, tirar dos grupos, tratar o e-mail conforme a política, recolher equipamentos.</li>
</ul>
<h3>Regras de ouro</h3>
<ul>
<li><b>Menor privilégio:</b> só o acesso que o trabalho exige.</li>
<li>Acesso é dado por <b>grupo</b>, não direto na conta.</li>
<li>Toda permissão tem <b>aprovação</b> do gestor ou do dono do recurso, registrada no ticket.</li>
<li>Nunca compartilhe contas, nunca peça senha, nunca crie "conta genérica" para facilitar.</li>
</ul>
<h3>No dia a dia de um Service Desk</h3>
<ul>
<li>Desbloquear, resetar senha e MFA vão estar na sua fila todos os dias. Faça rápido, mas sempre com verificação de identidade.</li>
<li>Pedido de acesso sem aprovação fica em "Aguardando aprovação", não "dá um jeitinho".</li>
<li>No SOC, cada uma dessas ações vira evento: 4740 (bloqueio), 4724 (reset de senha por um admin), 4728 (adicionado a grupo de segurança). Um reset de senha fora de um chamado é um alerta.</li>
</ul>
<h3>Pratique</h3>
<p>Na <b>Fila de chamados</b> há chamados de conta bloqueada, MFA, acesso a pasta, caixa cheia e novo funcionário, com Get-ADUser e net user para investigar.</p>
<h3>Erros comuns</h3>
<ul>
<li>Desbloquear a conta e não procurar a causa: ela bloqueia de novo em 10 minutos.</li>
<li>Reativar uma conta desativada porque "o usuário pediu".</li>
<li>Dar permissão direto na conta, ou acesso de administrador "para resolver logo".</li>
<li>No "mudou de setor", só adicionar acessos novos e esquecer de tirar os antigos.</li>
<li>Resetar MFA de alguém só porque a pessoa disse o nome e o setor.</li>
</ul>
<h3>Como explicar numa entrevista</h3>
<p><b>A user's account keeps locking out. How do you troubleshoot it?</b><br><i>I unlock it after verifying the user, then look for the source: usually a device or app still using an old password, like a phone mail app or a mapped drive. Event 4740 on the domain controller shows the caller computer name, which points to the device.</i></p>
<p><b>Someone asks for access to a shared folder. What do you do?</b><br><i>It's a service request, so I check who owns the folder and get approval from the owner or the manager. Then I add the user to the right security group, not directly to the folder, ask them to sign out and in again, and record the approval in the ticket.</i></p>""",
    "chk": [
        "Explicar a diferença entre Active Directory e Entra ID",
        "Diferenciar conta bloqueada, desativada e com senha expirada",
        "Descobrir por que uma conta bloqueia toda hora (evento 4740)",
        "Redefinir MFA com verificação de identidade",
        "Explicar licença, caixa compartilhada e tipos de grupo no Microsoft 365",
        "Aplicar o menor privilégio em entrou, mudou e saiu",
        "Acertar 8 de 10 no quiz de Contas e Acessos",
    ],
}

SD_TOPICS = [SD, ATEND, TROUBLE, CONTAS]

SD_RESUMOS = {
    "sd": [
        "Service Desk é o ponto único de contato entre os usuários e a TI.",
        "N0 autoatendimento, N1 primeiro atendimento, N2 especialistas, N3 engenharia ou fornecedor.",
        "Incidente = algo parou. Requisição = pedido padrão (com aprovação). Problema = causa raiz. Mudança = alteração planejada.",
        "Prioridade = impacto × urgência. Empresa parada = P1. Uma pessoa sem trabalhar = P3.",
        "SLA = prazo de primeira resposta e de solução para cada prioridade.",
        "Escalar com tudo pronto: sintoma, desde quando, quem, o que testou. Segurança: sempre avisar.",
    ],
    "atend": [
        "Roteiro: abertura, identificação, entender, registrar, resolver ou encaminhar, confirmar e encerrar.",
        "Perguntas abertas para entender, fechadas para confirmar, e parafrasear para não errar.",
        "Antes de reset de senha ou MFA: confirmar a identidade pelo processo (ligar de volta no número cadastrado).",
        "Urgência + autoridade + 'manda para outro número' = engenharia social.",
        "Usuário irritado: ouvir, reconhecer o impacto, desculpar-se pela situação e focar na solução.",
        "Nota do ticket: sintoma, o que verificou, o que fez, resultado e próximo passo. Sem opinião.",
    ],
    "trouble": [
        "7 passos: identificar, teoria, testar, planejar, aplicar, verificar, documentar.",
        "Divida: quem (um ou todos), o quê, quando (o que mudou?) e onde.",
        "Rede de baixo para cima: cabo, IP, gateway, internet, DNS, aplicação.",
        "169.254.x.x = sem DHCP. Ping no IP funciona e no nome não = DNS.",
        "Impressora travada: limpar a fila e reiniciar o Spooler. Outlook: testar na web.",
        "Uma mudança por vez, anote como estava e documente o que resolveu.",
    ],
    "contas": [
        "AD = contas da rede local. Entra ID = contas na nuvem. Quase sempre híbrido.",
        "Bloqueada = errou a senha. Desativada = de propósito. Senha expirada = passou do prazo.",
        "Bloqueio repetido = aparelho com senha antiga. O evento 4740 mostra o computador de origem.",
        "MFA: confirmar identidade e redefinir os métodos. MFA que a pessoa não pediu = segurança.",
        "Sem licença, sem e-mail. Caixa compartilhada: Full Access, Send As, Send on Behalf.",
        "Menor privilégio, acesso por grupo, aprovação registrada. Mudou de setor: tirar os acessos antigos.",
    ],
}

SD_Q = [
    # ---------------------------------------------------------------- Service Desk
    ("ServiceDesk", "O que é o Service Desk?",
     ["O ponto único de contato entre os usuários e a TI", "O time que só cuida de servidores", "O setor de compras de equipamentos", "Um programa antivírus"],
     "Quem precisa de algo da TI fala com o Service Desk, que registra, resolve ou encaminha.",
     ["Servidores ficam com times de infraestrutura (N2/N3).", "Compras é outro setor, embora o Service Desk possa abrir o pedido.", "Antivírus é uma ferramenta, não um time."],
     "No ITIL o termo é SPOC (Single Point of Contact): um lugar só para pedir ajuda.",
     "Uma pessoa sem acesso ao e-mail liga para o Service Desk, não para o time de servidores."),
    ("ServiceDesk", "O Outlook de uma usuária parou de abrir hoje. Que tipo de registro é?",
     ["Incidente", "Requisição de serviço", "Mudança", "Problema"],
     "Algo que funcionava parou: é incidente. O objetivo é restaurar o serviço rápido.",
     ["Requisição é um pedido de algo novo e padrão, não algo quebrado.", "Mudança é uma alteração planejada no ambiente.", "Problema é a causa raiz de vários incidentes; aqui é um caso só."],
     "Se 50 pessoas abrirem o mesmo incidente toda segunda, aí sim alguém abre um Problema para achar a causa.",
     "Ticket: INC0012345 'Outlook does not open' → categoria E-mail, tipo Incidente."),
    ("ServiceDesk", "Um funcionário pede acesso à pasta do RH. Que tipo de registro é?",
     ["Requisição de serviço, que precisa de aprovação", "Incidente crítico", "Problema", "Nenhum, é só dar o acesso"],
     "Nada está quebrado: é um pedido padrão. E acesso sempre precisa de aprovação do dono ou gestor.",
     ["Não há serviço parado.", "Problema é causa raiz de incidentes repetidos.", "Dar acesso sem aprovação fere o menor privilégio e não deixa registro."],
     "Requisições costumam vir do catálogo de serviços do portal, já com o fluxo de aprovação.",
     "RITM0004567 'Access to HR share' → aguardando aprovação da gestora do RH."),
    ("ServiceDesk", "Como se calcula a prioridade de um chamado?",
     ["Cruzando impacto (quantos são afetados) e urgência (quanto dá para esperar)", "Pela ordem de chegada, sempre", "Pelo cargo de quem abriu", "Pelo tom de voz do usuário"],
     "A matriz impacto × urgência dá a prioridade (P1 a P4) de forma justa e igual para todos.",
     ["Ordem de chegada ignora que um sistema parado para todos é mais grave.", "Cargo pode influenciar (VIP), mas a base é impacto e urgência.", "Gritar não muda o impacto no negócio."],
     "Algumas empresas sobem um nível para VIPs ou serviços críticos, mas sempre seguindo uma regra escrita.",
     "Sistema de vendas fora do ar para todos (impacto alto, urgência alta) = P1."),
    ("ServiceDesk", "Uma única pessoa não consegue trabalhar porque o computador não liga. Qual a prioridade mais provável?",
     ["P3 (média): impacto baixo, urgência alta", "P1 (crítica)", "P4 (baixa), pode esperar uma semana", "Não precisa de prioridade"],
     "Impacto baixo (uma pessoa) com urgência alta (parou) dá P3 na matriz padrão.",
     ["P1 é para impacto alto: empresa ou serviço crítico parado.", "A pessoa está parada, a urgência é alta.", "Todo chamado recebe prioridade."],
     "Prioridade não quer dizer desprezo: P3 ainda tem SLA, só que maior que o de um P1.",
     "Matriz: impacto baixo + urgência alta = P3."),
    ("ServiceDesk", "O que é SLA?",
     ["O prazo combinado de resposta e de solução para cada prioridade", "Um tipo de vírus", "O nome do sistema de tickets", "Uma senha de administrador"],
     "Service Level Agreement: o acordo de tempo entre a TI e o negócio.",
     ["Não tem relação com malware.", "Sistemas de ticket são ServiceNow, Jira etc.", "Não é credencial."],
     "Enquanto o ticket está 'Aguardando usuário', o relógio do SLA costuma pausar.",
     "P1: responder em 15 min e resolver em 4 h. P4: responder em 1 dia útil."),
    ("ServiceDesk", "O que significa escalar um chamado de forma funcional?",
     ["Passar para o time que tem o conhecimento ou o acesso para resolver", "Fechar o chamado", "Reclamar com o gestor do usuário", "Mudar a prioridade para P1"],
     "Funcional = para quem sabe ou pode. Hierárquico = avisar a coordenação.",
     ["Escalar não fecha: o chamado continua aberto com outro time.", "Isso não é escalonamento.", "A prioridade depende de impacto e urgência, não de escalar."],
     "Escalar bem é anexar tudo o que você já descobriu, para o N2 não recomeçar do zero.",
     "VPN caiu para todo o escritório → escalar para o N2 de Redes com os testes feitos."),
    ("ServiceDesk", "O que é FCR?",
     ["First Contact Resolution: resolver já no primeiro contato", "Firewall Control Rule", "Falha Crítica de Rede", "Um tipo de licença"],
     "É uma das métricas mais olhadas no Service Desk N1.",
     ["Não é regra de firewall.", "Não é sigla de falha.", "Não é licença."],
     "FCR alto é bom, mas não às custas de 'resolver' sem testar e o chamado voltar.",
     "Desbloquear a conta e confirmar com o usuário na mesma ligação conta como FCR."),
    ("ServiceDesk", "Quando um chamado deve ser fechado?",
     ["Depois que o usuário confirma que funciona (ou após o prazo sem resposta, pela política)", "Assim que você acha que resolveu", "Quando o turno acaba", "Nunca, fica aberto para sempre"],
     "Fechar sem confirmar gera reabertura e usuário insatisfeito.",
     ["Achar não é confirmar.", "O turno acabar não resolve nada: passe o chamado.", "Chamados abertos para sempre poluem o backlog."],
     "Muitas empresas usam 'Resolvido' e fecham automaticamente depois de 3 a 5 dias sem resposta.",
     "Status 'Resolved' → usuário confirma → 'Closed'."),
    ("ServiceDesk", "Dez pessoas ligam em 15 minutos dizendo que o sistema de vendas não abre. O que fazer?",
     ["Tratar como incidente grave: registrar um chamado principal, ligar os outros a ele e avisar a coordenação", "Atender os dez um por um, sem relacionar", "Esperar mais ligações para ter certeza", "Pedir para todos reiniciarem e fechar"],
     "Muitos afetados = possível incidente grave (major incident). Escalonamento hierárquico e comunicação.",
     ["Tratar separado esconde o tamanho do problema e duplica o trabalho.", "Esperar atrasa a resposta a um P1.", "Reiniciar não resolve um sistema central fora do ar."],
     "Os tickets dos usuários viram 'filhos' do incidente principal e recebem a mesma atualização.",
     "INC principal 'Sales system down' + 9 filhos; coordenador avisa a empresa por e-mail."),
    ("ServiceDesk", "Para que serve a base de conhecimento (KB)?",
     ["Guardar soluções testadas para resolver mais rápido e igual", "Guardar senhas dos usuários", "Substituir o sistema de tickets", "Guardar as fotos da equipe"],
     "Procure na KB antes de resolver, e escreva um artigo depois de resolver algo novo.",
     ["Senhas nunca vão para documentos.", "A KB complementa os tickets.", "Não é álbum de fotos."],
     "Bons artigos têm sintoma, causa, passo a passo e quando escalar.",
     "KB0010021: 'Printer queue stuck – clear queue and restart Spooler'."),
    ("ServiceDesk", "Por que passar pelo Service Desk ajuda quem quer trabalhar no SOC?",
     ["Ensina contas, redes, usuários e registro de tickets, que são a base dos alertas de segurança", "Não ajuda, são áreas sem relação", "Porque o SOC não usa tickets", "Porque no SOC não existe Active Directory"],
     "Os alertas do SOC falam de logins, bloqueios, acessos e e-mails: o dia a dia do Service Desk.",
     ["As áreas são muito ligadas.", "O SOC registra tudo em tickets e casos.", "O AD é um dos principais alvos e fontes de log."],
     "Muitos analistas de SOC júnior vieram do suporte: já sabem o que é normal no ambiente.",
     "Quem já desbloqueou contas entende rápido um alerta de 40 eventos 4625 seguidos de 4740."),
    # ---------------------------------------------------------------- Atendimento
    ("Atendimento", "Qual a primeira coisa a fazer antes de resetar a senha de alguém que ligou?",
     ["Confirmar a identidade pelo processo da empresa", "Resetar logo para ser rápido", "Pedir a senha atual", "Mandar a nova senha para o e-mail pessoal que a pessoa disser"],
     "Sem verificar a identidade, um golpista consegue a conta de outra pessoa só ligando.",
     ["Rapidez não justifica pular a verificação.", "A TI nunca precisa da senha de ninguém.", "Mandar para um contato não cadastrado é o que o golpista quer."],
     "Formas comuns: ligar de volta no número cadastrado, confirmar com o gestor, vídeo pelo Teams.",
     "'Vou te ligar de volta no ramal cadastrado para confirmar, tudo bem?'"),
    ("Atendimento", "O que é uma pergunta aberta?",
     ["Uma pergunta que faz a pessoa explicar com as palavras dela", "Uma pergunta de sim ou não", "Uma pergunta feita por e-mail", "Uma pergunta sem resposta"],
     "Abertas ajudam a entender; fechadas confirmam detalhes.",
     ["Sim ou não é pergunta fechada.", "O canal não define o tipo de pergunta.", "Toda boa pergunta busca uma resposta."],
     "Comece aberto ('o que acontece quando...') e feche com perguntas de sim ou não.",
     "'O que aparece na tela quando você tenta entrar?'"),
    ("Atendimento", "Para que serve parafrasear o que o usuário disse?",
     ["Confirmar que você entendeu certo antes de agir", "Mostrar que você sabe mais", "Gastar tempo da ligação", "Gravar a ligação"],
     "Repetir com suas palavras evita resolver o problema errado.",
     ["Não é para se exibir.", "Economiza tempo, porque evita retrabalho.", "Gravar é outra coisa."],
     "Se você entendeu errado, o usuário corrige na hora.",
     "'Então o Outlook abre, mas não chegam e-mails novos desde ontem, certo?'"),
    ("Atendimento", "Alguém liga dizendo ser o diretor, com muita pressa, e pede o código de MFA enviado para um número novo. O que isso parece?",
     ["Engenharia social: urgência, autoridade e contato novo", "Um pedido normal de diretor", "Um problema de rede", "Um chamado de impressora"],
     "Golpistas usam pressa e cargo alto para fazer você pular o processo.",
     ["Diretores também passam pela verificação.", "Não há sintoma de rede.", "Não tem relação com impressão."],
     "Recuse com educação, siga o processo, registre e avise a Segurança.",
     "Grupos como o Scattered Spider ficaram conhecidos por ligar para Service Desks pedindo reset de MFA."),
    ("Atendimento", "Qual a melhor forma de lidar com um usuário irritado?",
     ["Ouvir sem interromper, reconhecer o impacto e focar na solução com prazo realista", "Discutir até ele entender que a culpa é dele", "Desligar", "Prometer resolver em 5 minutos, mesmo sem saber"],
     "A pessoa quer ser ouvida e quer o problema resolvido.",
     ["Discutir piora e não resolve nada.", "Desligar gera reclamação e deixa o problema.", "Prometer o que não pode cumprir piora a confiança."],
     "Pedir desculpas pela situação não é assumir culpa: 'Sinto muito que isso esteja atrapalhando'.",
     "'Entendo, sem e-mail você não consegue responder os clientes. Vamos resolver isso agora.'"),
    ("Atendimento", "Qual a diferença entre nota interna e comentário no ticket?",
     ["A nota interna só a TI vê; o comentário vai para o usuário", "Não há diferença", "A nota interna é apagada no fim do dia", "O comentário só o gestor vê"],
     "No ServiceNow: work notes (internas) e additional comments (para o usuário).",
     ["São campos diferentes com públicos diferentes.", "Notas ficam no histórico.", "O comentário vai para quem abriu o chamado."],
     "Escreva detalhes técnicos na nota interna e uma explicação simples no comentário.",
     "Work note: 'gpresult shows policy not applied'. Comment: 'We are updating your settings.'"),
    ("Atendimento", "O que NÃO deve ir na nota de um ticket?",
     ["Opinião pessoal sobre o usuário", "O erro exato", "O que foi testado", "O resultado do teste"],
     "O ticket é um documento da empresa e pode ser lido pelo usuário, gestores e auditoria.",
     ["O erro exato é essencial.", "O que foi testado evita retrabalho.", "O resultado mostra se resolveu."],
     "Escreva fatos: o que aconteceu, o que você fez e o resultado.",
     "Errado: 'usuário confuso de novo'. Certo: 'user could not find the VPN app; guided to Start menu'."),
    ("Atendimento", "Antes de acessar o computador do usuário remotamente, o que fazer?",
     ["Pedir permissão e explicar o que vai fazer", "Conectar sem avisar", "Pedir a senha dele para entrar", "Desligar o antivírus dele"],
     "Respeito e transparência: a tela pode ter coisas pessoais ou confidenciais.",
     ["Conectar sem avisar assusta e quebra a confiança.", "A ferramenta remota não precisa da senha do usuário.", "Nunca desative proteções para dar suporte."],
     "Golpistas também 'dão suporte remoto': por isso o usuário deve saber exatamente quem está conectando.",
     "'Vou abrir o Quick Assist. Aparece um código, pode me ler?'"),
    ("Atendimento", "O usuário pergunta quando o problema vai ser resolvido, mas depende de outro time. O que responder?",
     ["Dizer quem está com o chamado e quando você dará a próxima notícia", "Prometer que fica pronto hoje", "Dizer que não é problema seu", "Não responder"],
     "Seja honesto sobre o que depende de você e mantenha a pessoa atualizada.",
     ["Prometer sem saber gera frustração.", "O chamado é do Service Desk até ser resolvido.", "Silêncio gera mais ligações e reclamações."],
     "Cumprir o prazo de retorno, mesmo sem solução, mantém a confiança.",
     "'Está com o time de Redes. Te dou notícia até as 15h, mesmo que ainda não tenha terminado.'"),
    ("Atendimento", "Em qual momento do atendimento você abre o ticket?",
     ["Durante a conversa, enquanto entende o problema", "Só se não conseguir resolver", "No fim do mês", "Nunca, telefone não gera ticket"],
     "Todo contato vira registro, inclusive o que se resolve em 2 minutos.",
     ["Sem ticket, o trabalho resolvido some das métricas e do histórico.", "Registrar depois faz perder detalhes.", "Todo canal gera ticket."],
     "Registrar na hora garante horário certo e detalhes exatos para o SLA e para o histórico.",
     "Enquanto a pessoa fala, você preenche: usuário, sintoma, categoria e prioridade."),
    ("Atendimento", "Como explicar um problema técnico para um usuário leigo?",
     ["Com palavras simples, sem jargão, e dizendo o que ele precisa fazer", "Com o máximo de termos técnicos", "Mandando o link da documentação da Microsoft", "Dizendo que é complicado demais"],
     "O objetivo é a pessoa entender o que aconteceu e o que fazer.",
     ["Jargão confunde e faz a pessoa ter vergonha de perguntar.", "Documentação técnica não é explicação.", "Dizer que é complicado não ajuda."],
     "Adapte a linguagem: com outro técnico, use termos técnicos; com o usuário, não.",
     "Em vez de 'sem lease do DHCP': 'seu computador não recebeu endereço da rede; vamos reconectar o cabo'."),
    # ---------------------------------------------------------------- Troubleshooting
    ("Troubleshooting", "Qual é o primeiro passo do método de troubleshooting?",
     ["Identificar o problema: perguntar, ver o erro e o que mudou", "Formatar o computador", "Trocar peças até funcionar", "Escalar para o N3"],
     "Sem entender o problema, você pode resolver a coisa errada.",
     ["Formatar é o último recurso, e apaga evidências.", "Trocar peças às cegas gasta tempo e dinheiro.", "Escalar sem investigar só passa o problema adiante."],
     "Os 7 passos: identificar, teoria, testar, planejar, aplicar, verificar, documentar.",
     "'O que mudou desde que funcionava?' resolve metade dos casos."),
    ("Troubleshooting", "O computador mostra o IP 169.254.10.23. O que isso indica?",
     ["Ele não recebeu endereço do DHCP", "Está conectado normalmente à internet", "Está com vírus", "O DNS está errado"],
     "169.254 é o endereço automático (APIPA) que o Windows usa quando o DHCP não responde.",
     ["Com 169.254 não há gateway: sem internet.", "Não indica malware.", "DNS é outra camada, acima do IP."],
     "Verifique cabo, porta da parede, switch e o serviço DHCP. Depois, ipconfig /renew.",
     "Sala inteira com 169.254 = switch da sala ou DHCP; uma máquina só = cabo ou placa."),
    ("Troubleshooting", "O ping em 8.8.8.8 responde, mas nenhum site abre pelo nome. O que é mais provável?",
     ["Problema de DNS", "Cabo desconectado", "Placa de rede queimada", "Monitor com defeito"],
     "Se o IP responde, a rede e a internet funcionam. Falta traduzir nomes: DNS.",
     ["Com o cabo solto, o ping não responderia.", "Placa queimada também não deixaria o ping passar.", "Monitor não tem relação com rede."],
     "Teste com nslookup site.com e confira os servidores DNS em ipconfig /all.",
     "nslookup intranet.empresa.local → 'Non-existent domain' com DNS 8.8.8.8 configurado à mão."),
    ("Troubleshooting", "Qual comando mostra IP, gateway, DNS e endereço MAC no Windows?",
     ["ipconfig /all", "ping", "dir", "tasklist"],
     "ipconfig /all mostra a configuração completa de cada placa de rede.",
     ["ping testa se um destino responde.", "dir lista arquivos.", "tasklist lista processos."],
     "Também mostra se o DHCP está ligado e quando o endereço foi obtido.",
     "ipconfig /all → 'DNS Servers . . . : 10.0.0.10'."),
    ("Troubleshooting", "A fila de impressão travou e nada imprime. Qual a solução clássica?",
     ["Limpar a fila e reiniciar o serviço Spooler", "Reinstalar o Windows", "Trocar a impressora", "Desligar o firewall"],
     "O Spooler é o serviço do Windows que gerencia a impressão. Um trabalho travado bloqueia a fila.",
     ["Reinstalar o Windows é exagero.", "A impressora pode estar perfeita.", "Firewall não trava fila local."],
     "PowerShell: Restart-Service Spooler. Antes, apague o trabalho travado da fila.",
     "Get-PrintJob mostra 'Error' no primeiro trabalho; remova e reinicie o Spooler."),
    ("Troubleshooting", "Só um setor não consegue imprimir; os outros imprimem na mesma impressora. Onde focar?",
     ["No que esse setor tem de diferente: driver, configuração ou rede daquele grupo", "Na impressora, que deve estar quebrada", "No servidor de e-mail", "Na internet da empresa"],
     "Se outros imprimem, a impressora funciona. O problema está no que é comum só ao setor afetado.",
     ["A impressora funciona para os outros.", "E-mail não tem relação com impressão.", "A impressão local não depende da internet."],
     "Divida o problema: quem é afetado e quem não é.",
     "Os PCs do Financeiro receberam um driver novo pela GPO ontem; os outros não."),
    ("Troubleshooting", "O Outlook não abre no computador, mas o e-mail funciona no Outlook na web. O que isso mostra?",
     ["A conta e o serviço estão ok; o problema é no computador (perfil, cache ou app)", "A conta foi apagada", "A licença acabou", "O servidor de e-mail caiu"],
     "Funcionar na web descarta conta, licença e serviço: sobra o lado do computador.",
     ["Com a conta apagada, a web também falharia.", "Sem licença, a web também não abriria a caixa.", "Com o servidor fora, a web também falharia."],
     "Próximos passos: modo de segurança (outlook /safe), novo perfil, reparar o Office.",
     "outlook.exe /safe abre? Um suplemento está travando o Outlook."),
    ("Troubleshooting", "Por que mudar uma coisa de cada vez?",
     ["Para saber exatamente o que resolveu (ou o que piorou)", "Para demorar mais", "Porque o Windows só aceita uma mudança por dia", "Não importa, pode mudar tudo junto"],
     "Mudanças isoladas permitem documentar a causa e desfazer se piorar.",
     ["O objetivo não é demorar.", "Não existe esse limite.", "Mudar tudo junto esconde a causa."],
     "Anote como estava antes de cada mudança.",
     "Trocou o cabo, testou: funcionou. Causa: cabo. Fácil de documentar."),
    ("Troubleshooting", "Para que servem gpupdate /force e gpresult /r?",
     ["Aplicar as políticas (GPO) agora e ver quais estão aplicadas", "Atualizar o Windows Update", "Trocar a senha do usuário", "Limpar o cache do navegador"],
     "Quando uma configuração da empresa não chegou na máquina, esses dois comandos mostram o porquê.",
     ["Windows Update é outro mecanismo.", "Senha se troca com Ctrl+Alt+Del ou no AD.", "Cache do navegador se limpa no navegador."],
     "Se a GPO não aparece no gpresult, verifique se o computador está na OU certa.",
     "gpresult /r → 'Applied Group Policy Objects: Default Domain Policy, Mapear-Drives-Financeiro'."),
    ("Troubleshooting", "Um computador está lento e o Gerenciador de Tarefas mostra um processo desconhecido usando 90% da CPU. O que fazer?",
     ["Ver o nome, o caminho e o editor do processo e, se suspeito, escalar para a Segurança", "Encerrar e ignorar", "Formatar na hora", "Desligar o antivírus para ganhar desempenho"],
     "Processo desconhecido com uso alto pode ser malware (um minerador, por exemplo).",
     ["Encerrar sem investigar pode deixar a ameaça voltar.", "Formatar apaga evidências que a Segurança precisaria.", "Nunca desligue a proteção."],
     "Clique com o botão direito → Abrir local do arquivo. Programas do Windows ficam em C:\\Windows\\System32, não em Downloads ou AppData.",
     "svch0st.exe (com zero) rodando de AppData = escalar para o SOC."),
    ("Troubleshooting", "O último passo do método de troubleshooting é:",
     ["Documentar a causa, a solução e o resultado", "Desligar o computador", "Apagar o ticket", "Comprar equipamento novo"],
     "Documentar faz o próximo técnico resolver em minutos.",
     ["Desligar não é passo de troubleshooting.", "O ticket é o registro do trabalho.", "Comprar algo não é passo do método."],
     "Se a solução for nova, transforme em artigo da base de conhecimento.",
     "Resolution notes: 'Cause: stuck print job. Cleared queue, restarted Spooler. Test page OK.'"),
    ("Troubleshooting", "Qual comando testa se a porta 443 de um servidor responde, no PowerShell?",
     ["Test-NetConnection servidor -Port 443", "ipconfig /flushdns", "Get-Process", "whoami"],
     "Testa a porta do serviço, não só se a máquina responde ao ping.",
     ["flushdns limpa o cache de DNS.", "Get-Process lista processos.", "whoami mostra a conta logada."],
     "Muitos servidores bloqueiam ping, mas a porta do serviço responde. Por isso testar a porta é melhor.",
     "Test-NetConnection erp.empresa.local -Port 443 → TcpTestSucceeded : True."),
    # ---------------------------------------------------------------- Contas
    ("Contas", "Qual a diferença entre conta bloqueada e conta desativada?",
     ["Bloqueada = errou a senha várias vezes; desativada = alguém desligou de propósito", "São a mesma coisa", "Desativada = senha expirada", "Bloqueada = foi apagada"],
     "Desbloquear é rotina; reativar uma conta desativada precisa de pedido aprovado.",
     ["Têm causas e tratamentos diferentes.", "Senha expirada é um terceiro estado.", "Conta apagada não aparece no AD."],
     "No Get-ADUser: LockedOut = bloqueada; Enabled = False = desativada.",
     "Ex-funcionário pede para 'desbloquear' a conta: está desativada; não reative."),
    ("Contas", "A conta de uma usuária bloqueia de novo minutos depois de desbloqueada. Causa mais comum?",
     ["Um aparelho ou programa tentando a senha antiga", "O teclado com defeito", "Falta de licença", "O monitor desligado"],
     "Celular com e-mail configurado, drive mapeado ou sessão antiga ficam tentando a senha velha.",
     ["Teclado com defeito não bloqueia sozinho, minutos depois, sem ninguém digitar.", "Licença não causa bloqueio de conta.", "Monitor não tem relação."],
     "O evento 4740 no controlador de domínio mostra o Caller Computer Name de onde vieram as tentativas.",
     "4740 → Caller Computer Name: CEL-ANA → o e-mail do celular dela ainda tem a senha antiga."),
    ("Contas", "Qual comando do PowerShell desbloqueia uma conta no AD?",
     ["Unlock-ADAccount", "Remove-ADUser", "Get-Process", "Restart-Computer"],
     "Unlock-ADAccount tira o bloqueio sem mudar a senha.",
     ["Remove-ADUser apaga a conta!", "Get-Process lista processos.", "Restart-Computer reinicia a máquina."],
     "Antes, Get-ADUser -Properties LockedOut confirma o estado.",
     "Unlock-ADAccount -Identity ana.souza"),
    ("Contas", "Um usuário novo entrou e diz que não tem e-mail, mas consegue logar no Windows. O que verificar primeiro?",
     ["Se a licença do Microsoft 365 com Exchange foi atribuída", "Se o monitor está ligado", "Se o antivírus está atualizado", "Se a impressora tem papel"],
     "Sem licença, a conta existe, mas a caixa de correio não é criada.",
     ["O login funciona, então o computador está ok.", "Antivírus não cria caixa de e-mail.", "Impressora não tem relação."],
     "Depois de atribuir a licença, a caixa pode levar alguns minutos para aparecer.",
     "Microsoft 365 admin center → Users → carlos.melo → Licenses: nenhuma marcada."),
    ("Contas", "O que é uma caixa de correio compartilhada?",
     ["Uma caixa que várias pessoas leem e usam, como financeiro@empresa", "A caixa pessoal do gestor", "Uma lista de distribuição", "Um backup de e-mails"],
     "Várias pessoas com permissão de Full Access e, se precisar, Send As.",
     ["A caixa pessoal pertence a uma pessoa.", "Lista de distribuição só repassa e-mails, não tem caixa.", "Backup é outra coisa."],
     "Caixas compartilhadas geralmente não precisam de licença até um certo tamanho (50 GB).",
     "Dar acesso à suporte@: Full Access para ler, Send As para responder como suporte@."),
    ("Contas", "Uma funcionária mudou do Financeiro para o RH. O que fazer com os acessos?",
     ["Dar os acessos do RH com aprovação e retirar os do Financeiro", "Só adicionar os do RH", "Dar acesso de administrador para evitar chamados", "Criar uma conta nova e deixar a antiga ativa"],
     "Quem muda de setor deve perder os acessos antigos (menor privilégio).",
     ["Somar acessos cria contas com poder demais: risco se forem comprometidas.", "Administrador para evitar chamado é um erro grave.", "Duas contas ativas para a mesma pessoa é desnecessário e arriscado."],
     "Esse acúmulo de acessos tem nome em inglês: privilege creep.",
     "Remove-ADGroupMember 'GG-Financeiro' carla.lima; Add-ADGroupMember 'GG-RH' carla.lima."),
    ("Contas", "Uma usuária recebe várias notificações de MFA que ela não pediu. O que isso indica?",
     ["Alguém tem a senha dela e está tentando entrar: caso de segurança", "Um defeito normal do celular", "Que ela precisa de mais licenças", "Que a impressora está offline"],
     "Notificação de MFA não pedida = a senha já foi descoberta. O atacante espera que ela aprove sem pensar (fadiga de MFA).",
     ["Não é defeito: cada notificação é uma tentativa real de login.", "Licença não gera notificações.", "Não tem relação com impressora."],
     "Ação: orientar a negar, trocar a senha, revogar sessões e avisar o SOC na hora.",
     "Técnica conhecida como MFA fatigue ou MFA bombing (MITRE T1621)."),
    ("Contas", "Como dar acesso a uma pasta de rede da forma certa?",
     ["Adicionar o usuário ao grupo de segurança que tem permissão na pasta, com aprovação", "Dar permissão direta na conta dele", "Dar acesso para Todos (Everyone)", "Passar a senha de um colega que já tem acesso"],
     "Acesso por grupo é fácil de manter e auditar.",
     ["Permissão direta vira bagunça e ninguém sabe quem tem acesso.", "Everyone expõe a pasta para a empresa toda.", "Compartilhar senha é proibido."],
     "Depois de adicionar ao grupo, a pessoa precisa sair e entrar no Windows para o acesso valer.",
     "Add-ADGroupMember 'GG-RH-Leitura' -Members carla.lima (aprovado pela gestora do RH)."),
    ("Contas", "Um funcionário foi desligado hoje. Qual a primeira ação na conta?",
     ["Desativar a conta e revogar as sessões no horário combinado", "Apagar a conta na hora", "Deixar ativa até o fim do mês", "Trocar o nome da conta e dar para outro"],
     "Desativar corta o acesso e mantém os dados que a empresa pode precisar.",
     ["Apagar perde dados; vem depois, pela política.", "Conta de ex-funcionário ativa é um risco grande.", "Contas não são passadas para outra pessoa."],
     "Revogar sessões é importante porque o login no celular e no navegador pode continuar válido.",
     "Disable-ADAccount joao.pereira; Revoke sessions no Entra ID."),
    ("Contas", "Qual a diferença entre Active Directory e Entra ID?",
     ["AD cuida das contas da rede local; Entra ID cuida das contas na nuvem da Microsoft", "São o mesmo programa com nomes diferentes", "Entra ID é um antivírus", "AD só funciona no Linux"],
     "Na maioria das empresas os dois existem e são sincronizados (híbrido).",
     ["Funcionam em lugares e com protocolos diferentes.", "Entra ID é o serviço de identidade da Microsoft na nuvem.", "AD é do Windows Server."],
     "O Entra ID se chamava Azure AD até 2023.",
     "Login no PC = AD. Login no Outlook na web e no Teams = Entra ID."),
    ("Contas", "O que é o SSPR?",
     ["Self-Service Password Reset: o próprio usuário troca a senha com MFA", "Um sistema de tickets", "Um tipo de firewall", "Uma licença de Office"],
     "Menos chamados de senha e menos risco de engenharia social no telefone.",
     ["Não é sistema de ticket.", "Não é firewall.", "Não é licença (embora dependa de uma)."],
     "O usuário cadastra métodos (Authenticator, telefone) e usa o portal quando esquece a senha.",
     "aka.ms/sspr → verificar com o Authenticator → nova senha."),
    ("Contas", "Por que não se deve dar acesso de administrador local 'para o usuário parar de abrir chamado'?",
     ["Porque, se a conta for comprometida, o atacante ganha controle total da máquina", "Porque o Windows fica lento", "Porque gasta licença", "Não há problema nenhum"],
     "Menor privilégio limita o estrago de um malware ou de um golpe.",
     ["Desempenho não é o motivo.", "Não consome licença.", "É um dos erros mais explorados em ataques."],
     "Para casos reais, existem soluções como a LAPS e a elevação temporária aprovada.",
     "Malware rodando como usuário comum não consegue desligar o antivírus; como administrador, consegue."),
]
