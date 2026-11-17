"""Mais dois tópicos do curso: Backup, Discos e BitLocker (fase 1, Service Desk) e Vulnerabilidades e Patches
(fase 2, SOC). Mesmo formato de topicos_novos.py; as perguntas de quiz ficam em EXTRA_Q (formato de quiz_novo.py)."""

BACKUP = {
    "id": "backup",
    "n": "Backup, Discos e BitLocker",
    "ic": "💾",
    "tags": ["Backup"],
    "st": """<p class="mu">Arquivo apagado, disco cheio, notebook pedindo uma "chave de recuperação": três chamados que todo Service Desk atende toda semana. E é o backup que salva a empresa quando chega um ransomware.</p>
<h3>O que é, em uma frase</h3>
<p>Backup é <b>uma cópia separada dos dados, guardada em outro lugar, que permite voltar a um momento anterior</b>. Se a cópia some junto com o original (mesmo disco, mesma conta, mesma rede), não é backup.</p>
<h3>Comparação do dia a dia</h3>
<p>Tirar foto dos documentos e guardar no celular ajuda se você perder a carteira. Mas se o celular estiver na carteira, você perde os dois. Backup bom fica <b>longe</b> do original.</p>
<h3>Backup, sincronização e versões não são a mesma coisa</h3>
<table><tr><th>O que é</th><th>Exemplo</th><th>Salva de quê</th></tr>
<tr><td><b>Sincronização</b></td><td>OneDrive, Google Drive</td><td>Do notebook quebrado. Mas se você apaga ou o ransomware criptografa, a mudança <b>sincroniza</b> também.</td></tr>
<tr><td><b>Versões e lixeira</b></td><td>Versões anteriores do Windows, histórico de versões e lixeira do OneDrive/SharePoint (cerca de 93 dias)</td><td>Do arquivo apagado ou estragado há pouco tempo.</td></tr>
<tr><td><b>Backup de verdade</b></td><td>Veeam, Azure Backup, fita, cópia na nuvem</td><td>De quase tudo, inclusive ransomware, se for separado e protegido.</td></tr></table>
<h3>A regra 3-2-1</h3>
<ul>
<li><b>3</b> cópias dos dados (o original e mais duas).</li>
<li><b>2</b> tipos de mídia ou lugar diferentes (disco e nuvem, por exemplo).</li>
<li><b>1</b> cópia fora da empresa (offsite).</li>
<li>Hoje se fala em <b>3-2-1-1-0</b>: mais 1 cópia <b>offline ou imutável</b> (ninguém consegue apagar, nem o administrador) e <b>0</b> erros no teste de restauração.</li>
</ul>
<h3>Tipos de backup</h3>
<ul>
<li><b>Completo:</b> copia tudo. Restaura fácil, mas é lento e ocupa muito espaço.</li>
<li><b>Incremental:</b> copia só o que mudou desde o <b>último backup</b> (de qualquer tipo). Rápido de fazer, mais peças para restaurar.</li>
<li><b>Diferencial:</b> copia o que mudou desde o <b>último completo</b>. Cresce a cada dia, mas restaura com só duas peças.</li>
</ul>
<h3>RPO e RTO: as duas perguntas do backup</h3>
<p><b>RPO</b> (Recovery Point Objective): <b>quanto dado posso perder?</b> Backup a cada 24 horas = até um dia de trabalho perdido. <b>RTO</b> (Recovery Time Objective): <b>em quanto tempo preciso voltar?</b> Um ERP parado pode ter RTO de 4 horas; uma pasta de arquivo morto, de dias.</p>
<h3>Restaurar um arquivo apagado</h3>
<ol>
<li>Pergunte o nome, a pasta e <b>quando</b> foi apagado ou estragado (para escolher a versão certa).</li>
<li>Comece pelo mais simples: lixeira, lixeira do OneDrive/SharePoint, histórico de versões.</li>
<li>Pasta da rede: <b>Versões anteriores</b> (clique direito na pasta), que vêm das cópias de sombra (Volume Shadow Copy) do servidor.</li>
<li>Escolha a cópia <b>de antes</b> do problema, restaure com outro nome e peça para a pessoa conferir.</li>
<li>Avise o que pode ter se perdido (o que mudou depois da cópia) e registre no ticket.</li>
</ol>
<h3>Disco cheio</h3>
<ul>
<li>Veja o espaço livre (Explorador de Arquivos, ou <code>Get-PSDrive C</code>) e o que ocupa mais: Downloads, vídeos, a lixeira, arquivos temporários.</li>
<li>Ferramentas do Windows: <b>Limpeza de Disco</b> (cleanmgr) e <b>Sensor de Armazenamento</b> (Storage Sense).</li>
<li><b>Nunca apague arquivos do usuário sem combinar com ele.</b> Mova para o OneDrive ou a pasta da rede, ou peça para ele escolher.</li>
<li>Disco cheio de repente, com arquivos que você não reconhece, pode ser malware ou alguém juntando dados para roubar: avise a Segurança.</li>
</ul>
<h3>BitLocker</h3>
<ul>
<li>BitLocker é a <b>criptografia de disco</b> do Windows: se roubarem o notebook, ninguém lê o disco em outro computador.</li>
<li>Usa o chip <b>TPM</b> da placa-mãe, que só libera o disco se o computador ligar do jeito de sempre.</li>
<li>Por isso pede a <b>chave de recuperação</b> (48 números) quando algo muda: atualização de BIOS, troca de peça, boot por pendrive, mudança na configuração de inicialização.</li>
<li>A tela mostra o <b>ID da chave</b> (os primeiros 8 caracteres). A chave fica guardada no Active Directory, no Entra ID ou na conta Microsoft. <b>Só passe a chave depois de confirmar a identidade</b>, e confira se o ID bate.</li>
<li>Chave pedida sem nenhuma mudança, várias vezes, ou para um notebook que foi dado como perdido? Acione a Segurança.</li>
</ul>
<h3>Ransomware e backup</h3>
<p>O ransomware tenta <b>apagar ou criptografar os backups primeiro</b>, para a empresa não ter saída a não ser pagar. Por isso o backup precisa estar separado da rede ou ser imutável, com senhas e contas diferentes das do dia a dia. E um backup que nunca foi testado é só uma esperança.</p>
<h3>No dia a dia de um Service Desk</h3>
<ul>
<li>"Apaguei sem querer": restaurar pela lixeira, pelas versões ou pelo backup, com a versão certa.</li>
<li>"Meu disco está cheio": achar o que ocupa e resolver com a pessoa.</li>
<li>"O notebook pede uma chave": confirmar identidade, conferir o ID e passar a chave.</li>
<li>Arquivos com extensão estranha e um bilhete pedindo resgate: <b>não é chamado comum</b>. Isolar a máquina e acionar a Segurança na hora.</li>
</ul>
<h3>Pratique na Fila de chamados</h3>
<p>Na Fila há chamados de BitLocker, disco cheio, arquivo apagado na pasta da rede e um caso de ransomware. Cada um passa pela triagem, perguntas, diagnóstico no terminal, solução e nota do ticket.</p>
<h3>Erros comuns</h3>
<ul>
<li>Achar que o OneDrive é backup: arquivo apagado ou criptografado também sincroniza.</li>
<li>Restaurar a cópia mais nova sem olhar a hora: ela pode ser de <b>depois</b> do problema.</li>
<li>Passar a chave do BitLocker sem confirmar quem está pedindo.</li>
<li>Apagar arquivos do usuário para liberar espaço sem perguntar.</li>
<li>Nunca testar a restauração.</li>
</ul>
<h3>Como explicar numa entrevista</h3>
<p><b>What is the 3-2-1 backup rule?</b><br><i>Keep three copies of the data, on two different types of storage, with one copy offsite. Today we also add one offline or immutable copy, because ransomware tries to delete the backups first, and we test restores regularly.</i></p>
<p><b>A laptop asks for a BitLocker recovery key. What do you do?</b><br><i>I verify the user's identity first. Then I ask for the key ID shown on the screen, find the matching recovery key in Active Directory or Entra ID and read it to them. I ask what changed, such as a BIOS update, and note it in the ticket. If nothing changed or it keeps happening, I involve security.</i></p>""",
    "chk": [
        "Diferenciar sincronização, versões e backup de verdade",
        "Explicar a regra 3-2-1 (e o 3-2-1-1-0)",
        "Diferenciar backup completo, incremental e diferencial",
        "Explicar RPO e RTO com um exemplo",
        "Restaurar um arquivo escolhendo a versão certa",
        "Atender um pedido de chave do BitLocker com segurança",
        "Acertar 8 de 10 no quiz de Backup",
    ],
}

VULN = {
    "id": "vuln",
    "n": "Vulnerabilidades e Patches",
    "ic": "🩹",
    "tags": ["Vuln"],
    "st": """<p class="mu">Quase todo ataque grande explora uma falha que já tinha correção. Saber ler um CVE, entender a nota CVSS e decidir o que corrigir primeiro aparece em muitas vagas de SOC e de segurança.</p>
<h3>O que é, em uma frase</h3>
<p>Vulnerabilidade é uma <b>fraqueza</b> num programa, sistema ou configuração que alguém pode usar para fazer o que não deveria. <b>Patch</b> é a correção que o fabricante publica.</p>
<h3>Comparação do dia a dia</h3>
<p>Uma janela que não tranca é a <b>vulnerabilidade</b>. O ladrão do bairro é a <b>ameaça</b>. A chance de ele entrar e o prejuízo se entrar é o <b>risco</b>. Trocar a tranca é o <b>patch</b>; colocar uma grade enquanto a tranca nova não chega é a <b>mitigação</b>.</p>
<h3>Vulnerabilidade, ameaça, exploit e risco</h3>
<ul>
<li><b>Vulnerabilidade:</b> a falha. Ex.: o servidor web aceita um comando escondido num campo de texto.</li>
<li><b>Ameaça:</b> quem ou o que pode se aproveitar (um grupo de ransomware, um robô que varre a internet).</li>
<li><b>Exploit:</b> o código ou técnica que usa a falha na prática.</li>
<li><b>Risco:</b> probabilidade × impacto. Falha grave num servidor sem acesso à internet e sem dados pode ter risco menor que uma falha média num site exposto.</li>
<li><b>Zero-day:</b> falha que o fabricante ainda não corrigiu (ou nem conhecia) e já está sendo explorada.</li>
</ul>
<h3>CVE, CWE e CVSS</h3>
<ul>
<li><b>CVE</b> é o "RG" de uma vulnerabilidade pública: <b>CVE-ano-número</b>. Ex.: <b>CVE-2021-44228</b> é o Log4Shell, na biblioteca Log4j.</li>
<li><b>CWE</b> é o <b>tipo</b> de erro de programação (ex.: injeção de SQL, estouro de buffer). Muitos CVEs, um mesmo CWE.</li>
<li><b>CVSS</b> dá uma nota de <b>0 a 10</b> para a gravidade técnica.</li>
</ul>
<table><tr><th>CVSS</th><th>Gravidade</th></tr>
<tr><td>0.1 a 3.9</td><td>Baixa (Low)</td></tr>
<tr><td>4.0 a 6.9</td><td>Média (Medium)</td></tr>
<tr><td>7.0 a 8.9</td><td>Alta (High)</td></tr>
<tr><td>9.0 a 10.0</td><td>Crítica (Critical)</td></tr></table>
<p>A nota olha coisas como: pela rede ou só com acesso físico? Precisa de login? Precisa que alguém clique? O que o atacante consegue (ler, alterar, derrubar)?</p>
<h3>CVSS não é tudo: KEV e EPSS</h3>
<ul>
<li>A empresa tem milhares de falhas "altas". Não dá para corrigir tudo de uma vez.</li>
<li>O catálogo <b>KEV</b> (Known Exploited Vulnerabilities) da CISA lista as falhas que <b>já estão sendo exploradas</b> de verdade. Estas vêm primeiro.</li>
<li>O <b>EPSS</b> estima a <b>probabilidade</b> de uma falha ser explorada nos próximos 30 dias.</li>
<li>Junte com o contexto do ativo: está <b>exposto na internet</b>? Tem dados sensíveis? É crítico para o negócio?</li>
</ul>
<h3>O ciclo de gestão de vulnerabilidades</h3>
<ol>
<li><b>Inventário:</b> saber quais máquinas e programas existem (não dá para proteger o que você não sabe que tem).</li>
<li><b>Descobrir:</b> scanners como Nessus, Qualys, OpenVAS ou o Defender Vulnerability Management.</li>
<li><b>Priorizar:</b> CVSS + KEV + EPSS + importância do ativo.</li>
<li><b>Corrigir:</b> aplicar o patch, atualizar a versão ou mudar a configuração. Se não der, <b>mitigar</b> (desligar o recurso, bloquear a porta, isolar) e registrar uma exceção com data para acabar.</li>
<li><b>Verificar:</b> escanear de novo para confirmar que fechou.</li>
<li><b>Reportar:</b> quanto falta, quanto tempo levamos, o que está atrasado.</li>
</ol>
<h3>Patch management na prática</h3>
<ul>
<li>A Microsoft publica correções na <b>Patch Tuesday</b>: a segunda terça-feira de cada mês. Falhas muito graves podem ganhar patch fora de hora (out-of-band).</li>
<li>Ferramentas: WSUS, Intune, Configuration Manager; no Linux, <code>apt</code> e <code>dnf</code>.</li>
<li>Testar antes num <b>grupo piloto</b>, depois liberar para todos, numa janela combinada (gestão de mudança).</li>
<li>Prazos comuns: crítica exposta na internet em dias; o resto em semanas.</li>
</ul>
<h3>No dia a dia de um SOC</h3>
<ul>
<li>Saiu um CVE crítico e explorado: <b>quais máquinas nossas têm essa versão?</b> Estão expostas? Procure no SIEM sinais de exploração nos logs do servidor e do WAF.</li>
<li>Alerta de exploração (ex.: tentativa de Log4Shell nos logs web): o servidor está vulnerável? Funcionou? Se sim, vira incidente.</li>
<li>Threat intel diz que um grupo está explorando um CVE: prioridade máxima para corrigir ou mitigar.</li>
<li>Exemplo clássico: o <b>WannaCry</b> (2017) explorou uma falha do SMB (MS17-010) que tinha patch havia dois meses.</li>
</ul>
<h3>Erros comuns</h3>
<ul>
<li>Corrigir só pela nota CVSS, sem olhar se a falha é explorada e se o ativo está exposto.</li>
<li>Esquecer de escanear de novo depois do patch.</li>
<li>Exceção sem data para terminar ("depois a gente vê").</li>
<li>Achar que zero-day é qualquer falha nova: é a que ainda não tem correção.</li>
<li>Aplicar patch em produção sem teste e sem janela, e derrubar o sistema.</li>
</ul>
<h3>Como explicar numa entrevista</h3>
<p><b>What is the difference between a vulnerability, a threat and a risk?</b><br><i>A vulnerability is a weakness, like an unpatched server. A threat is someone or something that can exploit it, like a ransomware group. Risk is the combination of how likely it is to happen and how much damage it would do.</i></p>
<p><b>How would you prioritise vulnerabilities?</b><br><i>Not only by the CVSS score. First the ones that are actively exploited, for example in the CISA KEV catalogue, then by exposure, internet-facing systems first, and by how critical the asset and its data are. If a patch can't be applied quickly, I'd apply a mitigation and track an exception with a deadline.</i></p>""",
    "chk": [
        "Diferenciar vulnerabilidade, ameaça, exploit e risco",
        "Ler um CVE e dizer a gravidade pela nota CVSS",
        "Explicar por que KEV e EPSS ajudam a priorizar",
        "Descrever o ciclo de gestão de vulnerabilidades",
        "Explicar a Patch Tuesday e o grupo piloto",
        "Dizer o que o SOC faz quando sai um CVE crítico",
        "Acertar 8 de 10 no quiz de Vulnerabilidades",
    ],
}

EXTRA_TOPICS = [BACKUP, VULN]

EXTRA_RESUMOS = {
    "backup": [
        "Backup é cópia separada e em outro lugar. Sincronização (OneDrive) não é backup: apagar também sincroniza.",
        "3-2-1: 3 cópias, 2 mídias, 1 fora. Hoje 3-2-1-1-0: mais 1 offline/imutável e 0 erros no teste.",
        "Completo copia tudo; incremental, o que mudou desde o último backup; diferencial, desde o último completo.",
        "RPO = quanto dado posso perder. RTO = em quanto tempo preciso voltar.",
        "Restaurar: escolha a versão de ANTES do problema, restaure com outro nome e confirme com a pessoa.",
        "BitLocker pede a chave quando algo muda (BIOS, peça, boot). Confirme identidade e o ID da chave.",
    ],
    "vuln": [
        "Vulnerabilidade = falha. Ameaça = quem explora. Exploit = como. Risco = probabilidade × impacto.",
        "CVE = o RG da falha (CVE-2021-44228 = Log4Shell). CWE = o tipo de erro. CVSS = nota de 0 a 10.",
        "CVSS: 0.1-3.9 baixa, 4-6.9 média, 7-8.9 alta, 9-10 crítica.",
        "Priorize com KEV (já explorada), EPSS (chance de ser explorada) e exposição do ativo.",
        "Ciclo: inventário, descobrir, priorizar, corrigir ou mitigar, verificar, reportar.",
        "Patch Tuesday = 2ª terça do mês. Teste no grupo piloto antes de liberar para todos.",
    ],
}

EXTRA_Q = [
    # ---------------------------------------------------------------- Backup, discos e BitLocker
    ("Backup", "Por que o OneDrive sozinho não é considerado backup?",
     ["Porque apagar ou criptografar um arquivo no PC também muda a cópia na nuvem", "Porque ele não guarda arquivos do Office", "Porque só funciona no celular", "Porque é mais lento que um pendrive"],
     "Sincronização espelha o que acontece no computador, inclusive o erro. Ajuda com versões e lixeira por um tempo, mas não substitui um backup separado.",
     ["Ele guarda qualquer tipo de arquivo.", "Funciona no Windows, no Mac e no celular.", "Velocidade não é o que define backup."],
     "Ransomware que criptografa a pasta sincronizada manda as versões criptografadas para a nuvem em minutos.",
     "Usuária apaga a pasta 'Clientes' sem querer: o OneDrive apaga lá também (ainda dá para tirar da lixeira por um tempo)."),
    ("Backup", "O que a regra 3-2-1 diz?",
     ["3 cópias, em 2 mídias ou lugares diferentes, com 1 cópia fora da empresa", "3 backups por dia, 2 por semana e 1 por mês", "3 discos, 2 servidores e 1 nuvem obrigatórios", "Restaurar em 3 horas, com 2 técnicos e 1 aprovação"],
     "É a regra clássica para não perder tudo de uma vez: cópias suficientes, em lugares diferentes, uma delas longe.",
     ["Não fala de frequência.", "Não exige equipamentos específicos.", "Não fala de tempo de restauração (isso é RTO)."],
     "A versão moderna, 3-2-1-1-0, acrescenta uma cópia offline ou imutável e zero erros no teste de restauração.",
     "Original no servidor, cópia num storage de backup e outra na nuvem, com bloqueio contra exclusão."),
    ("Backup", "Qual é a diferença entre backup incremental e diferencial?",
     ["Incremental copia o que mudou desde o último backup; diferencial, desde o último completo", "Incremental copia tudo; diferencial copia nada", "São a mesma coisa com nomes diferentes", "Diferencial é só para bancos de dados"],
     "O incremental é pequeno, mas a restauração precisa de várias peças. O diferencial cresce a cada dia, mas restaura com o completo e o último diferencial.",
     ["Quem copia tudo é o completo.", "Os dois são diferentes no que copiam e em como restauram.", "Os dois servem para qualquer tipo de dado."],
     "Muitas empresas fazem um completo no domingo e incrementais nos outros dias.",
     "Restaurar na quinta com incrementais: completo de domingo + seg + ter + qua + qui."),
    ("Backup", "O que significa RPO?",
     ["Quanto dado a empresa aceita perder, medido em tempo", "Quanto tempo leva para voltar a funcionar", "O número de cópias de backup", "O preço do armazenamento"],
     "RPO (Recovery Point Objective) define a frequência do backup: RPO de 1 hora exige cópia pelo menos de hora em hora.",
     ["Isso é o RTO (Recovery Time Objective).", "Número de cópias é a regra 3-2-1.", "Custo é consequência, não a definição."],
     "RPO olha para trás (o ponto de restauração); RTO olha para frente (o tempo até voltar).",
     "Backup toda noite = RPO de 24 horas: uma falha às 17h perde o trabalho do dia."),
    ("Backup", "Uma usuária apagou uma planilha da pasta da rede às 10h40. Há cópias de sombra das 07h00 e das 12h00. Qual restaurar?",
     ["A das 07h00, de antes da exclusão, avisando que o que mudou depois das 7h se perde", "A das 12h00, porque é a mais nova", "As duas, por cima do original", "Nenhuma: é melhor pedir para ela refazer"],
     "A cópia das 12h00 foi feita depois da exclusão e não tem o arquivo. Sempre escolha a versão de antes do problema.",
     ["A mais nova não tem o arquivo, ele já tinha sido apagado.", "Restaurar por cima pode sobrescrever trabalho atual.", "Se existe cópia, restaurar é o certo."],
     "Restaure com outro nome e peça para a pessoa conferir antes de substituir qualquer coisa.",
     "Versões anteriores → Orcamento_2027.xlsx de hoje 07:00 → Restaurar para… → Orcamento_2027 (restaurado).xlsx."),
    ("Backup", "Por que o BitLocker pede a chave de recuperação depois de uma atualização da BIOS?",
     ["Porque o TPM percebe que a inicialização mudou e não libera o disco sozinho", "Porque a atualização apagou o Windows", "Porque a senha do usuário expirou", "Porque o disco está com defeito"],
     "O TPM guarda medidas de como o computador liga. Mudou algo no firmware ou no boot, ele trava por segurança e pede a chave.",
     ["O Windows continua lá, só está criptografado.", "Senha de rede não tem relação com a chave do BitLocker.", "O disco está bom, só travado."],
     "Por isso o certo é suspender o BitLocker antes de atualizar a BIOS.",
     "Tela azul 'BitLocker recovery – Recovery key ID: 4F2A1C9B…' depois de atualizar o firmware."),
    ("Backup", "Antes de ler a chave do BitLocker para um usuário pelo telefone, o que fazer?",
     ["Confirmar a identidade pelo processo e conferir se o ID da chave na tela bate com o guardado", "Mandar a chave por e-mail para o gestor", "Ler todas as chaves que existem para o computador", "Pedir a senha do Windows dele"],
     "A chave abre o disco. Quem tem o notebook e a chave tem os dados: identidade primeiro, e só a chave certa.",
     ["E-mail pode ser lido por outra pessoa e deixa a chave guardada.", "Ler chaves erradas expõe outras chaves.", "Nunca se pede a senha de ninguém."],
     "Notebook dado como perdido pedindo chave? Não passe: acione a Segurança.",
     "Get-ADObject msFVE-RecoveryInformation → escolher a entrada com o ID 4F2A1C9B."),
    ("Backup", "Um disco C: está cheio. Qual é a atitude certa do suporte?",
     ["Ver o que ocupa espaço e, com o usuário, mover ou apagar o que ele não precisa, e rodar a Limpeza de Disco", "Apagar a pasta Downloads inteira sem avisar", "Formatar o computador", "Desligar a lixeira do Windows"],
     "Achar a causa e resolver junto com a pessoa: os arquivos são dela.",
     ["Apagar sem combinar pode destruir algo importante.", "Formatar é exagero e perde dados.", "Não resolve e tira uma proteção útil."],
     "Disco que enche de repente com arquivos estranhos pode ser sinal de malware ou de dados sendo juntados para roubo.",
     "Get-ChildItem por pasta mostra Downloads com 41 GB de vídeos de treinamento antigos."),
    ("Backup", "Por que o backup precisa ser offline ou imutável contra ransomware?",
     ["Porque o ransomware tenta apagar ou criptografar os backups que encontra na rede", "Porque backup online é mais caro", "Porque a lei proíbe backup na nuvem", "Porque assim o backup fica mais rápido"],
     "Sem backup, a empresa fica sem saída. Por isso os grupos de ransomware procuram e destroem os backups primeiro.",
     ["Custo não é o motivo.", "Não existe essa proibição.", "Imutável é sobre proteção, não velocidade."],
     "Imutável = ninguém consegue apagar ou alterar durante o prazo, nem um administrador com a senha roubada.",
     "Atacante com conta de admin do domínio apaga os backups do storage que estava no mesmo domínio."),
    ("Backup", "O que é o RTO?",
     ["O tempo máximo aceitável até o sistema voltar a funcionar", "A quantidade de dados que se aceita perder", "O tipo de backup mais rápido", "O nome da ferramenta de backup da Microsoft"],
     "RTO (Recovery Time Objective) responde 'em quanto tempo precisamos voltar?' e define a estratégia de restauração.",
     ["Isso é o RPO.", "RTO é uma meta de tempo, não um tipo de backup.", "Não é uma ferramenta."],
     "Sistema crítico com RTO de 1 hora pode precisar de um servidor reserva já pronto, não só de backup.",
     "ERP: RTO 4h. Pasta de arquivo morto: RTO 3 dias."),
    # ---------------------------------------------------------------- Vulnerabilidades e patches
    ("Vuln", "Qual é a diferença entre vulnerabilidade e ameaça?",
     ["Vulnerabilidade é a fraqueza; ameaça é quem ou o que pode se aproveitar dela", "São sinônimos", "Ameaça é a correção da vulnerabilidade", "Vulnerabilidade só existe em hardware"],
     "A janela que não tranca é a vulnerabilidade; o ladrão é a ameaça. Risco junta a chance de acontecer e o estrago.",
     ["São conceitos diferentes e os dois entram na conta do risco.", "Correção é o patch.", "Existem em software, hardware, configuração e até em processos."],
     "Risco = probabilidade × impacto.",
     "Servidor sem patch (vulnerabilidade) + grupo de ransomware varrendo a internet (ameaça) = risco alto."),
    ("Vuln", "O que é um CVE?",
     ["Um identificador público único de uma vulnerabilidade, como CVE-2021-44228", "Uma nota de gravidade de 0 a 10", "Um antivírus", "O tipo de erro de programação"],
     "CVE é o 'RG' da falha: CVE-ano-número. Todo mundo usa o mesmo ID para falar da mesma falha.",
     ["A nota é o CVSS.", "Não é uma ferramenta.", "O tipo de erro é o CWE."],
     "CVE-2021-44228 é o Log4Shell, na biblioteca Log4j, com CVSS 10.0.",
     "Boletim: 'Atualize o Log4j para corrigir o CVE-2021-44228'."),
    ("Vuln", "Uma falha tem CVSS 7.5. Qual é a gravidade?",
     ["Alta", "Crítica", "Média", "Baixa"],
     "Pelo CVSS v3: 7.0 a 8.9 é alta; 9.0 a 10.0, crítica; 4.0 a 6.9, média; 0.1 a 3.9, baixa.",
     ["Crítica começa em 9.0.", "Média vai até 6.9.", "Baixa vai até 3.9."],
     "A nota mede a gravidade técnica, não se a falha está sendo explorada no mundo real.",
     "CVSS 7.5 (High): explorável pela rede, sem login, permite ler dados."),
    ("Vuln", "O que é o catálogo KEV da CISA?",
     ["Uma lista de vulnerabilidades que já estão sendo exploradas na prática", "Uma lista de antivírus aprovados", "Um scanner de vulnerabilidades", "As falhas com nota CVSS 10"],
     "KEV (Known Exploited Vulnerabilities) mostra o que os atacantes já usam. É um dos melhores critérios para priorizar.",
     ["Não é sobre antivírus.", "É uma lista, não uma ferramenta de varredura.", "Tem falhas de várias notas: o critério é estar sendo explorada."],
     "Uma falha 'média' que está no KEV pode ser mais urgente que uma 'crítica' que ninguém explora.",
     "Relatório do scanner: 2.000 falhas altas, 14 estão no KEV → começar por essas 14."),
    ("Vuln", "Para que serve o EPSS?",
     ["Estimar a probabilidade de uma vulnerabilidade ser explorada nos próximos 30 dias", "Dar a nota de gravidade técnica", "Listar os patches da Microsoft", "Bloquear exploits automaticamente"],
     "O EPSS complementa o CVSS: além de quão grave, quão provável é que alguém use a falha logo.",
     ["Gravidade técnica é o CVSS.", "Patches da Microsoft saem na Patch Tuesday.", "É uma estimativa, não uma proteção."],
     "CVSS alto + EPSS alto + servidor exposto na internet = topo da fila.",
     "CVE com EPSS de 0.92: 92% de chance estimada de exploração em 30 dias."),
    ("Vuln", "O que é um zero-day?",
     ["Uma falha explorada antes de existir correção do fabricante", "Qualquer vulnerabilidade publicada hoje", "Um patch aplicado no mesmo dia", "Uma falha com nota CVSS 0"],
     "Zero-day: o fabricante teve 'zero dias' para corrigir. Não há patch, só mitigações e detecção.",
     ["Falha nova com patch disponível não é zero-day.", "Isso é só um patch rápido.", "CVSS 0 quer dizer sem impacto."],
     "Nesses casos o SOC depende de mitigação (bloquear, desligar o recurso) e de caçar sinais de exploração.",
     "Fabricante confirma exploração ativa e promete correção para a semana que vem: zero-day."),
    ("Vuln", "Qual a melhor ordem para priorizar a correção de vulnerabilidades?",
     ["Primeiro as exploradas (KEV) em sistemas expostos e críticos, depois por gravidade e importância do ativo", "Só pela nota CVSS, da maior para a menor", "Pela ordem alfabética dos servidores", "Primeiro as mais antigas, sempre"],
     "Juntar exploração real, exposição e importância do ativo coloca o esforço onde o risco é maior.",
     ["Só o CVSS ignora se a falha é explorada e onde está.", "Ordem alfabética não tem relação com risco.", "Antiguidade sozinha não diz o risco."],
     "Muitas empresas usam prazos (SLA) por faixa: crítica exposta em dias, alta em semanas.",
     "VPN exposta na internet com falha no KEV: corrigir hoje, antes da falha 'crítica' num servidor isolado."),
    ("Vuln", "Quando é a Patch Tuesday da Microsoft?",
     ["Na segunda terça-feira de cada mês", "Toda terça-feira", "No primeiro dia útil do mês", "Uma vez por ano"],
     "A Microsoft publica as correções mensais na segunda terça. Falhas urgentes podem ganhar patch fora de hora (out-of-band).",
     ["É mensal, não semanal.", "Não é no primeiro dia útil.", "É todo mês."],
     "Muitas equipes testam no grupo piloto na semana seguinte e liberam para todos depois.",
     "Patch Tuesday → piloto na quarta → todos na terça seguinte, numa janela de mudança."),
    ("Vuln", "Não dá para aplicar o patch agora num sistema crítico. O que fazer?",
     ["Aplicar uma mitigação (desligar o recurso, bloquear a porta, isolar) e registrar uma exceção com data", "Ignorar até o próximo ano", "Desligar o scanner para a falha não aparecer", "Aplicar o patch em produção sem teste mesmo assim"],
     "Mitigação reduz o risco enquanto a correção não vem. A exceção com dono e prazo garante que não seja esquecida.",
     ["Ignorar deixa a porta aberta.", "Esconder o problema não diminui o risco.", "Patch sem teste pode derrubar o sistema crítico."],
     "Isso também se chama controle compensatório.",
     "Exceção: servidor legado, porta 445 bloqueada no firewall, patch na janela de 15/12, dono: time de infraestrutura."),
    ("Vuln", "Saiu um CVE crítico explorado num produto que a empresa usa. O que o SOC faz?",
     ["Descobre quais máquinas têm a versão afetada e se estão expostas, e procura sinais de exploração nos logs", "Espera o time de infraestrutura aplicar o patch e não faz mais nada", "Desliga todos os servidores da empresa", "Só abre um chamado e fecha em seguida"],
     "Corrigir é com a infraestrutura, mas o SOC precisa saber se a falha já foi usada contra a empresa e vigiar enquanto o patch não chega.",
     ["Se já houve exploração, o patch não remove o atacante que entrou.", "Desligar tudo é desproporcional.", "Sem investigar, uma invasão pode passar despercebida."],
     "Threat intel costuma trazer IOCs e assinaturas da exploração para procurar no SIEM e no WAF.",
     "Log4Shell: procurar '${jndi:' nos logs web dos últimos dias e ver se algum servidor fez conexão estranha depois."),
]
