# Agenda de Testemunho Público (TPL)

Sistema web com login (usuário e senha), perfis e escala.

## Perfis
- **Ancião**: acesso total (inclusive usuários). **Servo Responsável pelo TPL**: horários, lançar semana, escala e envio da programação, sem acesso a usuários. **Servo Ministerial**: monta a escala.
- **Servo Ministerial**: monta a escala (confirma quem se ofereceu).
- **Publicador**: entra só com o usuário (sem senha), marca a disponibilidade e vê a escala e a programação.

## Rodar no computador
    pip install -r requirements.txt
    python app.py
Abra http://localhost:5000. No primeiro acesso crie o Ancião administrador.

## Publicar na internet (exemplo com servidor/VPS)
    gunicorn -w 2 -b 0.0.0.0:8000 app:app
Use HTTPS (Nginx + Certbot, ou um serviço como Render / PythonAnywhere).
O banco é o arquivo `tpl.db`: faça backup copiando esse arquivo. Nunca publique o arquivo `.secret`.
