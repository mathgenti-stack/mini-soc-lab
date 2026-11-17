"""Perguntas de RH da simulação de entrevista (as técnicas vêm dos próprios tópicos, seção
"Como explicar numa entrevista"). Cada uma: id, pergunta (q), tradução (pt), dica (tip) e um modelo (a)."""

RH = [
    {
        "id": "rh-1",
        "q": "Can you tell me a little about yourself?",
        "pt": "Fale um pouco sobre você.",
        "tip": "Quase sempre é a primeira. Use presente → passado → futuro em 1 minuto: o que você faz hoje, "
               "o que estudou e praticou (este curso e o lab contam), e a vaga que você quer.",
        "a": "I'm moving into IT and security. Over the last months I've studied networking, Windows, Linux and logs, "
             "and I practise in a home lab where I analyse real logs and handle simulated support tickets. "
             "I'm looking for my first role where I can help users, learn fast and grow into a SOC analyst.",
    },
    {
        "id": "rh-2",
        "q": "Tell me about a problem you solved.",
        "pt": "Conte sobre um problema que você resolveu.",
        "tip": "Use o método STAR: Situação, Tarefa, Ação e Resultado. Pode ser um caso do lab ou da Fila de chamados. "
               "Fale mais da Ação (o que VOCÊ fez) e termine com o resultado.",
        "a": "In my lab I investigated a suspicious login. My task was to find out if the account was compromised. "
             "I filtered the failed and successful logon events, found many failures from one IP followed by a success, "
             "and checked what ran after the logon. As a result I wrote a short report with the timeline and the next steps.",
    },
    {
        "id": "rh-3",
        "q": "What is your greatest weakness?",
        "pt": "Qual é o seu maior ponto fraco?",
        "tip": "Escolha um ponto fraco real, mas que não impeça o trabalho, e mostre o que você já faz para melhorar. "
               "Evite \"sou perfeccionista\".",
        "a": "I sometimes spend too long trying to solve a problem alone. I've learnt to set a time limit, document "
             "what I tried and then ask for help or escalate, which is also how a good service desk works.",
    },
    {
        "id": "rh-4",
        "q": "Why should we hire you?",
        "pt": "Por que deveríamos contratar você?",
        "tip": "Junte três coisas: uma qualidade sua, uma prova (algo que você já fez) e o que você vai entregar para a empresa.",
        "a": "I'm curious, I document what I do and I learn fast. I've already practised the daily tasks of this role "
             "in a lab, such as triaging tickets, reading logs and writing clear notes, so I can contribute quickly "
             "and keep improving with the team.",
    },
]
