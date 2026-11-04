# Shown when the terminal opens (sourced from ~/.bashrc). Kept short and in both languages.
PS1='\[\e[1;32m\]analyst@soc-lab\[\e[0m\]:\[\e[1;34m\]\w\[\e[0m\]\$ '
alias ll='ls -la'

if [ -z "$SOC_LAB_WELCOMED" ]; then
  export SOC_LAB_WELCOMED=1
  cat <<'EOF'
Mini SOC Lab - Terminal
  EN  Your logs are in ~/logs (read-only). Try:  ls logs   then   head logs/linux_auth.log
      Each challenge is in the Terminal tab of the dashboard. Type 'exit' to restart the shell.
  PT  Seus logs estão em ~/logs (somente leitura). Tente:  ls logs   e depois   head logs/linux_auth.log
      Os desafios estão na aba Terminal do dashboard. Digite 'exit' para reiniciar o shell.

EOF
fi
