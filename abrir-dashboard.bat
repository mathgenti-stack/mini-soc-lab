@echo off
REM Abre o dashboard do Mini SOC Lab.
REM Coloque este arquivo dentro da pasta do projeto (ao lado de streamlit_app.py) e de dois cliques.

cd /d "%~dp0"

if not exist "streamlit_app.py" (
  echo ERRO: este arquivo precisa ficar dentro da pasta do projeto, ao lado de streamlit_app.py
  pause
  exit /b
)

if not exist ".venv\Scripts\activate.bat" (
  echo Primeira vez: criando o ambiente e instalando as dependencias. Pode demorar alguns minutos...
  python -m venv .venv
  call .venv\Scripts\activate.bat
  pip install -r requirements.txt
) else (
  call .venv\Scripts\activate.bat
)

echo.
echo Abrindo o dashboard em http://localhost:8501
echo NAO feche esta janela enquanto estiver usando o dashboard.
echo.
streamlit run streamlit_app.py
pause
