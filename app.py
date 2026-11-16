import os, sqlite3, secrets, time, datetime as dt
from functools import wraps
from flask import Flask, g, request, session, redirect, render_template, flash, abort
from markupsafe import Markup
from jinja2 import DictLoader
from werkzeug.security import generate_password_hash, check_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.environ.get("TPL_DB", os.path.join(BASE, "tpl.db"))
KF = os.path.join(BASE, ".secret")
if not os.path.exists(KF):
    open(KF, "w").write(secrets.token_hex(32))
app = Flask(__name__)
app.secret_key = open(KF).read()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  PERMANENT_SESSION_LIFETIME=dt.timedelta(days=30))
DIAS = ["Segunda", "Terça", "Quarta", "Quinta", "Sexta", "Sábado", "Domingo"]  # weekday()
ROLES = {"anciao": "Ancião", "servo_tpl": "Servo Responsável pelo TPL",
         "servo": "Servo Ministerial", "publicador": "Publicador"}
ADM = ("anciao", "servo_tpl")          # configuram horários e usuários
GEST = ("anciao", "servo_tpl", "servo")  # montam a escala
SCHEMA = """
create table if not exists users(id integer primary key, nome text not null, usuario text unique not null,
  hash text not null, role text not null, ativo integer default 1);
create table if not exists locais(id integer primary key, nome text not null, endereco text default '');
create table if not exists turnos(id integer primary key, local_id integer references locais(id) on delete cascade,
  dow integer, ini text, fim text, vagas integer);
create table if not exists disp(user_id integer references users(id) on delete cascade, data text,
  turno_id integer references turnos(id) on delete cascade, primary key(user_id,data,turno_id));
create table if not exists escala(user_id integer references users(id) on delete cascade, data text,
  turno_id integer references turnos(id) on delete cascade, primary key(user_id,data,turno_id));
create table if not exists cfg(k text primary key, v text);
create table if not exists semanas(inicio text primary key);
"""

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
        g.db.execute("pragma foreign_keys=on")
    return g.db

@app.teardown_appcontext
def close(e):
    d = g.pop("db", None)
    if d: d.close()

def q(sql, *a): return db().execute(sql, a).fetchall()
def x(sql, *a):
    c = db().execute(sql, a); db().commit(); return c

def me():
    if "uid" not in session: return None
    r = q("select * from users where id=? and ativo=1", session["uid"])
    return r[0] if r else None

def need(*roles):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            u = me()
            if not u:
                if request.headers.get("X-Requested-With"): return {"ok": False, "erro": "Sessão expirada. Saia e entre novamente."}, 401
                return redirect("/login")
            if roles and u["role"] not in roles: abort(403)
            g.u = u
            return f(*a, **k)
        return w
    return deco

@app.before_request
def csrf():
    if request.method == "POST" and request.form.get("_t") != session.get("_t"):
        abort(400)

@app.context_processor
def ctx():
    session.setdefault("_t", secrets.token_hex(16))
    return dict(T=session["_t"], H=Markup('<input type=hidden name=_t value="%s">' % session["_t"]), u=me(),
                ROLES=ROLES, DIAS=DIAS, ADM=ADM, GEST=GEST)

def janela():
    r = q("select v from cfg where k='janela'")
    return int(r[0]["v"]) if r else 14

def agenda(lid=None):
    t, out = dt.date.today(), []
    for sg in lancadas():
        for i in range(7):
            d = sg + dt.timedelta(i)
            if d < t: continue
            sql = "select t.*,l.nome ln from turnos t join locais l on l.id=t.local_id where dow=?" + (" and t.local_id=?" if lid else "") + " order by ini"
            ts = q(sql, d.weekday(), *([lid] if lid else []))
            if ts: out.append((d, ts))
    return out

def mapa(sql, *a):
    m = {}
    for r in q(sql, *a):
        m.setdefault("%s|%s" % (r["data"], r["turno_id"]), []).append(dict(r))
    return m

# ---------- acesso ----------
fails = {}
@app.route("/login", methods=["GET", "POST"])
def login():
    if not q("select 1 from users limit 1"): return redirect("/setup")
    if request.method == "POST":
        ip = request.remote_addr; n, t = fails.get(ip, (0, 0))
        if n >= 5 and time.time() - t < 300:
            flash("Muitas tentativas. Aguarde 5 minutos.")
        else:
            r = q("select * from users where usuario=? and ativo=1", request.form["usuario"].strip().lower())
            if r and (r[0]["role"] == "publicador" or (r[0]["hash"] and check_password_hash(r[0]["hash"], request.form.get("senha", "")))):
                session.clear(); session.permanent = True; session["uid"] = r[0]["id"]
                fails.pop(ip, None); return redirect("/")
            fails[ip] = (n + 1, time.time()); flash("Usuário ou senha incorretos.")
    return render_template("login")

@app.route("/setup", methods=["GET", "POST"])
def setup():
    if q("select 1 from users limit 1"): return redirect("/login")
    if request.method == "POST":
        f = request.form
        if len(f["senha"]) < 8 or not f["usuario"].strip() or not f["nome"].strip():
            flash("Preencha tudo (senha com no mínimo 8 caracteres).")
        else:
            x("insert into users(nome,usuario,hash,role) values(?,?,?,'anciao')", f["nome"].strip(),
              f["usuario"].strip().lower(), generate_password_hash(f["senha"]))
            for nm in ("Padaria", "Derba", "Pantanal"):
                default_turnos(x("insert into locais(nome) values(?)", nm).lastrowid)
            flash("Conta criada. Entre para continuar."); return redirect("/login")
    return render_template("setup")

@app.post("/logout")
def logout():
    session.clear(); return redirect("/login")

@app.route("/senha", methods=["GET", "POST"])
@need()
def senha():
    if request.method == "POST":
        f = request.form
        if not check_password_hash(g.u["hash"], f["atual"]) or len(f["nova"]) < 8:
            flash("Senha atual incorreta ou nova senha curta (mínimo 8).")
        else:
            x("update users set hash=? where id=?", generate_password_hash(f["nova"]), g.u["id"])
            flash("Senha alterada.")
    return render_template("senha")

# ---------- disponibilidade (semanas lançadas) ----------
def seg_de(d): return d - dt.timedelta(d.weekday())
def lancadas(): return [dt.date.fromisoformat(r["inicio"]) for r in q("select inicio from semanas order by inicio")]

@app.route("/")
@need()
def home():
    k = lambda r: "%s|%s" % (r["data"], r["turno_id"])
    mine = {k(r) for r in q("select * from disp where user_id=?", g.u["id"])}
    esc = {k(r) for r in q("select * from escala where user_id=?", g.u["id"])}
    t0, days = dt.date.today(), []
    for s in lancadas():
        if s + dt.timedelta(6) < t0: continue
        for i in range(7):
            d = s + dt.timedelta(i)
            ts = [] if d < t0 else [{"id": r["id"], "ini": r["ini"], "fim": r["fim"], "lid": r["local_id"]} for r in
                  q("select * from turnos where dow=? order by ini", d.weekday())]
            days.append({"i": d.isoformat(), "w": d.weekday(), "n": d.day, "m": d.month - 1, "ts": ts})
    locs = [{"id": r["id"], "nome": r["nome"]} for r in q("select id,nome from locais order by id")]
    return render_template("disp", days=days, locs=locs, mine=sorted(mine), esc=sorted(esc))

@app.post("/toggle")
@need()
def toggle():
    def err(m):
        if request.headers.get("X-Requested-With"): return {"ok": False, "erro": m}, 400
        flash(m); return redirect("/")
    try:
        d, t = request.form["data"], int(request.form["turno"]); dd = dt.date.fromisoformat(d)
    except (KeyError, ValueError): return err("Dados inválidos.")
    tu = q("select * from turnos where id=?", t)
    if not tu or tu[0]["dow"] != dd.weekday(): return err("Horário inexistente.")
    if dd < dt.date.today() or seg_de(dd) not in lancadas(): return err("Esta semana não está liberada. Aguarde o responsável lançá-la.")
    cur = bool(q("select 1 from disp where user_id=? and data=? and turno_id=?", g.u["id"], d, t))
    want = request.form.get("on")
    want = (not cur) if want is None else want == "1"
    if want and not cur: x("insert into disp values(?,?,?)", g.u["id"], d, t)
    elif cur and not want: x("delete from disp where user_id=? and data=? and turno_id=?", g.u["id"], d, t)
    if request.headers.get("X-Requested-With"): return {"ok": True}
    return redirect("/")

@app.route("/semanas")
@need(*ADM)
def semanas():
    seg, on = seg_de(dt.date.today()), set(lancadas())
    ws = []
    for k in range(8):
        s = seg + dt.timedelta(7 * k)
        ws.append({"i": s.isoformat(), "p": "%s a %s" % (s.strftime("%d/%m"), (s + dt.timedelta(5)).strftime("%d/%m")), "on": s in on})
    return render_template("semanas", ws=ws)

@app.post("/semanas/<act>")
@need(*ADM)
def semanas_act(act):
    try: s = seg_de(dt.date.fromisoformat(request.form["s"]))
    except (KeyError, ValueError): abort(400)
    if act == "lancar": x("insert or ignore into semanas values(?)", s.isoformat())
    elif act == "fechar": x("delete from semanas where inicio=?", s.isoformat())
    return redirect("/semanas")

SEMANAS = """{% extends "base" %}{% block c %}<div class=card><h2>Lançar semana</h2><p class=m>Os publicadores só podem se colocar à disposição nas semanas lançadas. Lance a semana quando for recolher a disponibilidade e feche quando terminar.</p>
{% for w in ws %}<div class=s><div><b>{{w.p}}</b> {% if w.on %}<span class=ok>● Lançada</span>{% else %}<span class=m>Fechada</span>{% endif %}</div><form method=post action="/semanas/{{'fechar' if w.on else 'lancar'}}">{{H}}<input type=hidden name=s value="{{w.i}}"><button class="{{'d' if w.on}}">{{'Fechar semana' if w.on else 'Lançar semana'}}</button></form></div>{% endfor %}</div>{% endblock %}"""

# ---------- escala ----------
@app.route("/escala")
@need()
def escala():
    locs = q("select * from locais order by id")
    try: sel = int(request.args["l"])
    except (KeyError, ValueError): sel = locs[0]["id"] if locs else 0
    em = mapa("select e.data,e.turno_id,u.id,u.nome from escala e join users u on u.id=e.user_id where u.ativo=1")
    dm = mapa("select e.data,e.turno_id,u.id,u.nome from disp e join users u on u.id=e.user_id where u.ativo=1")
    return render_template("escala", ag=agenda(sel), em=em, dm=dm, locs=locs, sel=sel)

@app.post("/escala/set")
@need(*GEST)
def escala_set():
    f = request.form; d, t, u, op = f["data"], int(f["turno"]), int(f["uid"]), f["op"]
    tu = q("select * from turnos where id=?", t)[0]
    if op == "add":
        n = q("select count(*) c from escala where data=? and turno_id=?", d, t)[0]["c"]
        if n >= tu["vagas"]: flash("O turno já está completo.")
        elif q("select 1 from escala e join turnos o on o.id=e.turno_id where e.user_id=? and e.data=? and o.id!=? and o.ini<? and ?<o.fim",
               u, d, t, tu["fim"], tu["ini"]): flash("Conflito: o publicador já está escalado nesse horário.")
        else: x("insert or ignore into escala values(?,?,?)", u, d, t)
    else:
        x("delete from escala where user_id=? and data=? and turno_id=?", u, d, t)
    return redirect("/escala?l=%s" % tu["local_id"])

# ---------- configuração ----------
@app.route("/config")
@need(*ADM)
def config():
    return render_template("config", locais=q("select * from locais order by nome"), janela=janela(),
                           turnos=q("select t.*,l.nome ln from turnos t join locais l on l.id=t.local_id order by dow,ini"))

@app.post("/config/<act>")
@need(*ADM)
def config_act(act):
    f = request.form
    if act == "janela":
        x("insert or replace into cfg values('janela',?)", str(min(max(int(f["n"]), 7), 60)))
    elif act == "local" and f["nome"].strip():
        c = x("insert into locais(nome,endereco) values(?,?)", f["nome"].strip(), f.get("end", "").strip())
        if f.get("padrao"): default_turnos(c.lastrowid)
    elif act == "padrao": default_turnos(int(f["id"]))
    elif act == "turno":
        ds = f.getlist("dow")
        if ds and f["ini"] < f["fim"] and f.get("local"):
            for d in ds:
                x("insert into turnos(local_id,dow,ini,fim,vagas) values(?,?,?,?,?)", int(f["local"]), int(d), f["ini"], f["fim"], max(1, int(f["vagas"])))
        else: flash("Escolha local, dias e um horário válido.")
    elif act == "del" and f["kind"] in ("locais", "turnos"):
        x("delete from %s where id=?" % f["kind"], int(f["id"]))
    return redirect("/config")

@app.route("/usuarios", methods=["GET", "POST"])
@need("anciao")
def usuarios():
    if request.method == "POST":
        f = request.form; a = f["act"]
        if f.get("role") == "anciao" and g.u["role"] != "anciao": abort(403)
        if a == "add":
            if (f["role"] != "publicador" and len(f["senha"]) < 8) or not f["usuario"].strip() or f["role"] not in ROLES:
                flash("Dados inválidos (Anciãos e Servos precisam de senha com no mínimo 8 caracteres).")
            else:
                try:
                    x("insert into users(nome,usuario,hash,role) values(?,?,?,?)", f["nome"].strip(),
                      f["usuario"].strip().lower(), generate_password_hash(f["senha"]) if f["senha"] else "", f["role"])
                except sqlite3.IntegrityError: flash("Esse usuário já existe.")
        else:
            i = int(f["id"]); eu = i == g.u["id"]
            if a == "save":
                if len(f.get("senha", "")) >= 8: x("update users set hash=? where id=?", generate_password_hash(f["senha"]), i)
                cur = q("select hash from users where id=?", i)[0]["hash"]
                if not eu and f["role"] in ROLES:
                    if f["role"] != "publicador" and not cur: flash("Defina uma senha para promover este usuário.")
                    else: x("update users set role=?,ativo=? where id=?", f["role"], 1 if f.get("ativo") else 0, i)
            elif a == "del" and not eu: x("delete from users where id=?", i)
    return render_template("users", us=q("select * from users order by nome"))

# ---------- horários padrão e programação semanal ----------
MANHA = [("07:00", "09:00"), ("09:00", "11:00")]
TARDE = [("14:00", "16:00"), ("16:00", "18:00")]

def default_turnos(lid):
    """Segunda a sábado; quinta (índice 3) apenas de manhã."""
    for dow in range(6):
        for ini, fim in MANHA + ([] if dow == 3 else TARDE):
            if not q("select 1 from turnos where local_id=? and dow=? and ini=? and fim=?", lid, dow, ini, fim):
                x("insert into turnos(local_id,dow,ini,fim,vagas) values(?,?,?,?,2)", lid, dow, ini, fim)

def semana(seg):
    cols = q("select * from locais order by id")
    out = []
    for i in range(6):
        d = seg + dt.timedelta(i)
        ts = q("select * from turnos where dow=? order by ini", i)
        slots = sorted({(t["ini"], t["fim"]) for t in ts})
        if not slots: continue
        em = mapa("select e.data,e.turno_id,u.nome from escala e join users u on u.id=e.user_id where e.data=?", d.isoformat())
        rows, tarde = [], False
        for ini, fim in slots:
            if ini >= "12:00" and not tarde:
                rows.append({"sep": "TARDE"}); tarde = True
            cells = []
            for l in cols:
                t = [t for t in ts if t["local_id"] == l["id"] and t["ini"] == ini and t["fim"] == fim]
                n = [p["nome"] for p in em.get("%s|%s" % (d.isoformat(), t[0]["id"]), [])] if t else []
                cells.append(" e ".join(n))
            rows.append({"t": "%s as %s" % (ini, fim), "c": cells, "z": len([r for r in rows if "t" in r]) % 2})
        out.append({"title": "%s %s" % (DIAS[i].upper(), d.strftime("%d/%m")), "cols": [l["nome"] for l in cols], "rows": rows})
    return out

@app.route("/programacao")
@need()
def programacao():
    try: seg = dt.date.fromisoformat(request.args["s"])
    except (KeyError, ValueError): seg = dt.date.today()
    seg -= dt.timedelta(seg.weekday())
    per = "%s a %s" % (seg.strftime("%d/%m"), (seg + dt.timedelta(5)).strftime("%d/%m"))
    days = semana(seg)
    txt = ["*PROGRAMAÇÃO SEMANAL – TESTEMUNHO COM OS CARRINHOS*", per]
    for dd in days:
        txt.append("\n*%s*" % dd["title"])
        for r in dd["rows"]:
            if "t" not in r: continue
            linhas = ["• %s: %s" % (c, n) for c, n in zip(dd["cols"], r["c"]) if n]
            if linhas: txt.append("%s\n%s" % (r["t"], "\n".join(linhas)))
    txt = "\n".join(txt)
    can = g.u["role"] in ADM
    data = {"titulo": "PROGRAMAÇÃO SEMANAL TESTEMUNHO COM OS CARRINHOS", "per": per, "days": days, "txt": txt}
    return render_template("prog", days=days, per=per, can=can, txt=txt if can else "", data=data if can else {},
                           prev=(seg - dt.timedelta(7)).isoformat(), nxt=(seg + dt.timedelta(7)).isoformat())

PROG = """{% extends "base" %}{% block c %}
<style>.prog{min-width:640px;border:2px solid #333;max-width:900px;margin:0 auto;background:#fff;color:#222;-webkit-print-color-adjust:exact;print-color-adjust:exact}
.ptitle{background:#5f5f5f;color:#fff;text-align:center;padding:10px;font-weight:600}.pt{border-collapse:collapse;width:100%}
.pt td{border:1px solid #333;padding:5px;text-align:center;font-size:13px;font-weight:600;text-transform:uppercase}
.pt .ph td{background:#c2540a;color:#fff}.pt .ps td{background:#8a8a8a;color:#fff}.pt .z0 td{background:#fff}.pt .z1 td{background:#ead9c3}
@media print{nav,.r,.fl{display:none}@page{margin:8mm}body{background:#fff}.w{padding:0}}</style>
<div class=r style="margin-bottom:10px"><a href="/programacao?s={{prev}}"><button class=g>‹ Semana anterior</button></a><a href="/programacao?s={{nxt}}"><button class=g>Próxima ›</button></a>
{% if can %}<button onclick="img()">Baixar imagem</button><button class=g onclick="window.print()">Salvar PDF</button>
<button class=on onclick="zap()">Enviar imagem no WhatsApp</button><a href="https://wa.me/?text={{txt|urlencode}}" target=_blank><button class=g>Enviar texto no WhatsApp</button></a>{% endif %}</div>{% if not can %}<p class=m>Somente o Ancião e o Servo Responsável pelo TPL podem enviar a programação.</p>{% endif %}
<div class=tw><div class=prog><div class=ptitle>PROGRAMAÇÃO SEMANAL TESTEMUNHO COM OS CARRINHOS<br><small>{{per}}</small></div>
{% for dd in days %}<table class=pt><tr class=ph><td>{{dd.title}}</td>{% for c in dd.cols %}<td>{{c}}</td>{% endfor %}</tr>
{% for r in dd.rows %}{% if r.sep %}<tr class=ps><td colspan="{{dd.cols|length+1}}">{{r.sep}}</td></tr>{% else %}<tr class="z{{r.z}}"><td>{{r.t}}</td>{% for c in r.c %}<td>{{c}}</td>{% endfor %}</tr>{% endif %}{% endfor %}</table>{% else %}<p style="padding:14px">Nenhum horário configurado.</p>{% endfor %}</div></div>
{% if can %}<script>
var DATA={{ data|tojson }};
function draw(){
 var W=1000,sc=2,rh=30,fw=170,D=DATA.days,n=D.length?D[0].cols.length:1,cw=(W-fw)/n;
 var H=44;D.forEach(function(d){H+=rh*(1+d.rows.length)});
 var c=document.createElement("canvas");c.width=W*sc;c.height=H*sc;var x=c.getContext("2d");x.scale(sc,sc);
 x.fillStyle="#fff";x.fillRect(0,0,W,H);
 function cell(px,py,w,h,bg,fg,t){x.fillStyle=bg;x.fillRect(px,py,w,h);x.strokeStyle="#333";x.strokeRect(px,py,w,h);x.fillStyle=fg;x.font="bold 13px Arial,sans-serif";x.textAlign="center";x.textBaseline="middle";x.fillText(t,px+w/2,py+h/2,w-8)}
 cell(0,0,W,44,"#5f5f5f","#fff",DATA.titulo+"  ·  "+DATA.per);
 var y=44;
 D.forEach(function(d){
  cell(0,y,fw,rh,"#c2540a","#fff",d.title);d.cols.forEach(function(k,i){cell(fw+i*cw,y,cw,rh,"#c2540a","#fff",k.toUpperCase())});y+=rh;
  d.rows.forEach(function(r){
   if(r.sep){cell(0,y,W,rh,"#8a8a8a","#fff",r.sep)}
   else{var bg=r.z?"#ead9c3":"#fff";cell(0,y,fw,rh,bg,"#222",r.t);r.c.forEach(function(t,i){cell(fw+i*cw,y,cw,rh,bg,"#222",t.toUpperCase())})}
   y+=rh});
 });
 return c}
function img(){draw().toBlob(function(b){var a=document.createElement("a");a.href=URL.createObjectURL(b);a.download="programacao-tpl.png";a.click()})}
function zap(){draw().toBlob(function(b){var f=new File([b],"programacao-tpl.png",{type:"image/png"});
 if(navigator.canShare&&navigator.canShare({files:[f]}))navigator.share({files:[f],text:DATA.txt}).catch(function(){});
 else{alert("Seu aparelho não permite enviar a imagem direto. Ela será baixada; depois anexe no WhatsApp.");img()}})}
</script>{% endif %}{% endblock %}"""

# ---------- templates ----------
CSS = """<style>:root{--bg:#eeece9;--c:#fff;--t:#2b2b2b;--m:#6b6b6b;--b:#d6d0c7;--p:#c2540a;--p2:#ead9c3;--ok:#6b4a2b;--okb:#ead9c3;--wr:#a8480a;--wrb:#fbe3d0;--er:#9b2c2c;--erb:#f3dcda}
@media(prefers-color-scheme:dark){:root{--bg:#1f1f1f;--c:#2a2a2a;--t:#eee;--m:#a8a8a8;--b:#444;--p:#d9661a;--p2:#3b2f25;--ok:#e0c4a0;--okb:#4a3a2b;--wr:#f0a060;--wrb:#4a2e1a;--er:#f09090;--erb:#4a2424}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--t);font:15px/1.45 system-ui,sans-serif}.w{max-width:960px;margin:0 auto;padding:14px}
nav{background:#5f5f5f;padding:6px;border-radius:10px;display:flex;gap:4px;flex-wrap:wrap;align-items:center;border-bottom:1px solid var(--b);margin-bottom:14px;padding-bottom:6px}nav a{padding:8px 11px;color:#eee;text-decoration:none;border-radius:7px}nav a:hover{background:#c2540a;color:#fff}nav .sp{flex:1}
.card{background:var(--c);border:1px solid var(--b);border-radius:10px;padding:12px;margin-bottom:12px}h2,h3{margin:0 0 8px}h3{font-size:14px;color:var(--p)}.m{color:var(--m);font-size:13px}
input,select{background:var(--bg);color:var(--t);border:1px solid var(--b);border-radius:7px;padding:8px;font:inherit;max-width:100%}
button{background:var(--p);color:#fff;border:0;border-radius:7px;padding:8px 13px;font:inherit;cursor:pointer}button.g{background:var(--p2);color:var(--p)}button.d{background:var(--erb);color:var(--er)}button.on{background:#6b4a2b;color:#fff}
.r{display:flex;flex-wrap:wrap;gap:8px;align-items:center}.s{display:flex;justify-content:space-between;align-items:center;gap:8px;border:1px solid var(--b);border-radius:8px;padding:10px;margin-bottom:8px;background:var(--bg)}
.ch{display:inline-flex;align-items:center;gap:4px;border-radius:99px;padding:3px 10px;margin:4px 4px 0 0;font-size:13px;background:var(--okb);color:var(--ok)}.ch button{background:none;color:inherit;padding:0 4px}.ch.a{background:var(--wrb);color:var(--wr)}
.ok{color:var(--ok)}.fl{background:var(--wrb);color:var(--wr);padding:8px 10px;border-radius:8px;margin-bottom:10px}table{width:100%;border-collapse:collapse}td{padding:6px;border-bottom:1px solid var(--b)}textarea{width:100%;height:200px;background:var(--bg);color:var(--t);border:1px solid var(--b);border-radius:7px;padding:8px}.w{max-width:1100px}button,input,select{min-height:42px}input[type=checkbox]{min-height:0;width:18px;height:18px}.ch button,button.ch{min-height:32px}.dg{display:grid;gap:12px;grid-template-columns:repeat(auto-fill,minmax(290px,1fr))}.dg .card{margin:0}.tw{overflow-x:auto}.lay{display:block}.lay .card{margin-bottom:12px}.cal{display:grid;grid-template-columns:repeat(7,1fr);gap:5px}.cal b{text-align:center;font-size:12px;color:var(--m)}.dy{position:relative;border:1px solid var(--b);background:var(--c);border-radius:10px;min-height:54px;padding:4px;text-align:center;color:var(--t);font-size:16px;font-weight:600}.dy small{display:block;font-size:10px;font-weight:400;color:var(--m)}.dy.off{opacity:.3;pointer-events:none}.dy.hoje{outline:2px solid var(--p);outline-offset:1px}.dy.sel{background:var(--p);color:#fff;border-color:var(--p)}.dy.sel small,.dy.sel i{color:#fff}.dy i{position:absolute;top:2px;right:5px;font-style:normal;font-size:11px;font-weight:700;color:var(--p)}.cards{display:grid;gap:10px;grid-template-columns:repeat(2,1fr)}.tc{border:2px solid var(--b);background:var(--c);border-radius:12px;padding:12px 6px;text-align:center;font:inherit;color:var(--t);min-height:96px}.tc b{display:block;font-size:18px}.tc span{font-size:12px;color:var(--m)}.tc.esc{border-color:var(--p)}.tc.on{background:#6b4a2b;border-color:#6b4a2b}.tc.on span,.tc.on b{color:#fff}.fl2{display:flex;gap:6px;flex-wrap:wrap;margin:6px 0}.fl2 button{background:var(--p2);color:var(--p)}.fl2 button.on{background:var(--p);color:#fff}@media(min-width:700px){.w{padding:20px}.cards{grid-template-columns:repeat(3,1fr)}.dy{min-height:60px}}@media(min-width:1000px){.lay{display:grid;grid-template-columns:400px 1fr;gap:16px;align-items:start}.cards{grid-template-columns:repeat(4,1fr)}}@media(max-width:600px){input,select{font-size:16px}.s{flex-direction:column;align-items:stretch}nav .sp{display:none}nav a{padding:8px 9px;font-size:14px}.card td{display:block;border:0;padding:2px 6px}.card tr{display:block;border-bottom:1px solid var(--b);padding:6px 0}}.ab{display:flex;gap:6px;overflow-x:auto;margin-bottom:12px}.ab a{flex:1;min-width:110px}.ab>button{flex:1;min-width:110px}.ab button{width:100%;background:var(--p2);color:var(--p);font-weight:600;border-radius:10px 10px 0 0;border-bottom:3px solid transparent}.ab button.on{background:var(--c);border-bottom-color:var(--p)}</style>"""
BASE_T = """<!doctype html><html lang=pt-BR><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Agenda TPL</title>""" + CSS + """<div class=w>
{% if u %}<nav><a href="/">Minha disponibilidade</a><a href="/escala">Escala</a><a href="/programacao">Programação</a>{% if u.role in ADM %}<a href="/semanas">Lançar semana</a><a href="/config">Horários e locais</a>{% endif %}{% if u.role=='anciao' %}<a href="/usuarios">Usuários</a>{% endif %}<span class=sp></span>{% if u.role!='publicador' %}<a href="/senha">{{u.nome}} · {{ROLES[u.role]}}</a>{% else %}<a>{{u.nome}}</a>{% endif %}<form method=post action="/logout">{{H}}<button class=g>Sair</button></form></nav>{% endif %}
{% for m in get_flashed_messages() %}<div class=fl>{{m}}</div>{% endfor %}{% block c %}{% endblock %}</div>"""
FORM = lambda t, campos, btn: ('{% extends "base" %}{% block c %}<div class=card style="max-width:380px;margin:40px auto"><h2>' + t + '</h2><form method=post>{{H}}' + campos + '<button style="width:100%">' + btn + '</button></form></div>{% endblock %}')
IN = lambda n, p, ty="text": '<p><input name=%s placeholder="%s" type=%s required style="width:100%%"></p>' % (n, p, ty)
TPL = {
 "base": BASE_T,
 "login": FORM("Entrar", IN("usuario", "Usuário") + '<p><input name=senha type=password placeholder="Senha (somente Anciãos e Servos)" style="width:100%"></p>', "Entrar"),
 "setup": FORM("Primeiro acesso: criar Ancião administrador", IN("nome", "Nome completo") + IN("usuario", "Usuário") + IN("senha", "Senha (mín. 8)", "password"), "Criar conta"),
 "senha": FORM("Alterar senha", IN("atual", "Senha atual", "password") + IN("nova", "Nova senha (mín. 8)", "password"), "Salvar"),
 "disp": """{% extends "base" %}{% block c %}
<div id=app></div>
<script>
var T="{{T}}",DAYS={{days|tojson}},LOCS={{locs|tojson}},MINE=new Set({{mine|tojson}}),ESC=new Set({{esc|tojson}}),SEL=-1,L=0;
var MS=["jan","fev","mar","abr","mai","jun","jul","ago","set","out","nov","dez"],WD=["Seg","Ter","Qua","Qui","Sex","Sáb","Dom"],WF=["Segunda","Terça","Quarta","Quinta","Sexta","Sábado","Domingo"];
function E(s){return String(s).replace(/[&<>"]/g,function(c){return{"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]})}
function tsOf(d){return d.ts.filter(function(t){return t.lid===LOCS[L].id})}
function cnt(d){return tsOf(d).filter(function(t){return MINE.has(d.i+"|"+t.id)}).length}
function firstDay(){for(var i=0;i<DAYS.length;i++)if(tsOf(DAYS[i]).length)return i;return -1}
function grp(d,nome,f){
 var a=tsOf(d).filter(f);if(!a.length)return "";
 return '<h3 style="margin:14px 0 8px">'+nome+'</h3><div class=cards>'+a.map(function(t){
  var k=d.i+"|"+t.id,on=MINE.has(k),e=ESC.has(k);
  return '<button class="tc'+(on?" on":"")+(e?" esc":"")+'" data-a="tg" data-v="'+k+'"><b>'+t.ini+"–"+t.fim+"</b><span>"+(e?"★ Escalado":on?"✓ Disponível":"Toque para marcar")+"</span></button>"}).join("")+"</div>"}
function html(){
 var h='<div class=ab>'+LOCS.map(function(l,i){return '<button class="'+(i===L?"on":"")+'" data-a="loc" data-v="'+i+'">'+E(l.nome)+"</button>"}).join("")+"</div>";
 if(SEL<0)return h+"<div class=card>Nenhum horário neste ponto nas semanas lançadas.</div>";
 var d=DAYS[SEL];
 h+='<div class=lay><div class=card><h3>1. Escolha o dia — '+E(LOCS[L].nome)+'</h3><div class=cal>'+WD.map(function(w){return "<b>"+w+"</b>"}).join("");
 for(var k=0;k<DAYS[0].w;k++)h+="<span></span>";
 DAYS.forEach(function(x,ix){var c=cnt(x);
  h+='<button class="dy'+(tsOf(x).length?"":" off")+(SEL===ix?" sel":"")+'" data-a="day" data-v="'+ix+'">'+(c?"<i>"+c+"</i>":"")+x.n+"<small>"+(x.n==1||ix==0?MS[x.m]:"&nbsp;")+"</small></button>"});
 h+='</div><p class=m style="margin:8px 0 0">O número no canto mostra quantos horários você marcou neste ponto.</p></div>';
 h+='<div class=card><h3>2. '+WF[d.w]+", "+d.n+" de "+MS[d.m]+" — toque nos horários</h3>"+grp(d,"Manhã",function(t){return t.ini<"12"})+grp(d,"Tarde",function(t){return t.ini>="12"})+"</div></div>";
 return h}
function draw(){document.getElementById("app").innerHTML=html()}
function tg(k){
 var was=MINE.has(k);was?MINE.delete(k):MINE.add(k);draw();var p=k.split("|");
 function undo(m){was?MINE.add(k):MINE.delete(k);draw();alert(m||"Não foi possível salvar. Tente de novo.")}
 fetch("/toggle",{method:"POST",credentials:"same-origin",headers:{"X-Requested-With":"fetch"},body:new URLSearchParams({_t:T,data:p[0],turno:p[1],on:was?"0":"1"})})
 .then(function(r){return r.json().then(function(j){if(!r.ok||!j.ok)undo(j.erro)},function(){undo("Sessão expirada. Saia e entre novamente.")})}).catch(function(){undo()})}
document.getElementById("app").addEventListener("click",function(e){
 var b=e.target.closest("[data-a]");if(!b)return;var a=b.dataset.a,v=b.dataset.v;
 if(a==="loc"){L=+v;if(SEL<0||!tsOf(DAYS[SEL]).length)SEL=firstDay();draw()}
 else if(a==="day"){SEL=+v;draw()}else if(a==="tg")tg(v)});
if(!DAYS.length||!LOCS.length)document.getElementById("app").innerHTML='<div class=card><b>Aguarde.</b> O responsável ainda não lançou a semana para você se colocar à disposição.</div>';
else{SEL=firstDay();draw()}
</script>{% endblock %}""",
 "escala": """{% extends "base" %}{% block c %}<div class=ab>{% for l in locs %}<a href="/escala?l={{l.id}}"><button class="{{'on' if l.id==sel}}">{{l.nome}}</button></a>{% endfor %}</div><div class=dg>{% for d,ts in ag %}<div class=card><h3>{{DIAS[d.weekday()]}} {{d.strftime('%d/%m')}}</h3>{% for t in ts %}{% set k=d.isoformat()~'|'~t.id %}{% set a=em.get(k,[]) %}{% set ids=a|map(attribute='id')|list %}
<div class=s style="display:block"><b>{{t.ini}}–{{t.fim}}</b> · {{t.ln}} <span class=m>({{a|length}}/{{t.vagas}} vagas)</span><br>
{% for p in a %}<span class=ch>{{p.nome}}{% if u.role in GEST %}<form method=post action="/escala/set" style="display:inline">{{H}}<input type=hidden name=data value="{{d.isoformat()}}"><input type=hidden name=turno value="{{t.id}}"><input type=hidden name=uid value="{{p.id}}"><input type=hidden name=op value=del><button>×</button></form>{% endif %}</span>{% endfor %}
{% if u.role in GEST %}{% for p in dm.get(k,[]) if p.id not in ids %}<form method=post action="/escala/set" style="display:inline">{{H}}<input type=hidden name=data value="{{d.isoformat()}}"><input type=hidden name=turno value="{{t.id}}"><input type=hidden name=uid value="{{p.id}}"><input type=hidden name=op value=add><button class="ch a">+ {{p.nome}}</button></form>{% endfor %}{% endif %}</div>{% endfor %}</div>
{% else %}<div class=card>Nenhuma semana lançada ou nenhum horário neste ponto.</div>{% endfor %}</div>
<div class=card style="margin-top:12px"><a href="/programacao"><button>Ver programação</button></a></div>{% endblock %}""",
 "config": """{% extends "base" %}{% block c %}

<div class=card><h2>Locais</h2><form method=post action="/config/local" class=r>{{H}}<input name=nome placeholder="Ex.: Praça central" required><input name=end placeholder="Endereço"><label><input type=checkbox name=padrao value=1 checked> horários padrão</label><button>Adicionar</button></form><table>{% for l in locais %}<tr><td>{{l.nome}}<br><span class=m>{{l.endereco}}</span></td><td><form method=post action="/config/padrao" style="display:inline">{{H}}<input type=hidden name=id value="{{l.id}}"><button class=g>Gerar horários padrão</button></form> <form method=post action="/config/del" style="display:inline">{{H}}<input type=hidden name=kind value=locais><input type=hidden name=id value="{{l.id}}"><button class=d>Excluir</button></form></td></tr>{% endfor %}</table></div>
<div class=card><h2>Horários de uso (turnos)</h2>{% if locais %}<form method=post action="/config/turno">{{H}}<p><select name=local>{% for l in locais %}<option value="{{l.id}}">{{l.nome}}</option>{% endfor %}</select></p><p>{% for i in [0,1,2,3,4,5,6] %}<label style="margin-right:8px"><input type=checkbox name=dow value="{{i}}"> {{DIAS[i][:3]}}</label>{% endfor %}</p><p class=r><input type=time name=ini value="08:00"><input type=time name=fim value="10:00"><label>Vagas <input type=number name=vagas value=2 min=1 max=20 style="width:64px"></label><button>Adicionar</button></p></form>{% else %}<p class=m>Cadastre um local primeiro.</p>{% endif %}
<table>{% for t in turnos %}<tr><td>{{DIAS[t.dow]}}</td><td>{{t.ini}}–{{t.fim}}</td><td>{{t.ln}}</td><td>{{t.vagas}} vagas</td><td><form method=post action="/config/del">{{H}}<input type=hidden name=kind value=turnos><input type=hidden name=id value="{{t.id}}"><button class=d>Excluir</button></form></td></tr>{% endfor %}</table></div>{% endblock %}""",
 "users": """{% extends "base" %}{% block c %}<div class=card><h2>Novo usuário</h2><form method=post class=r>{{H}}<input type=hidden name=act value=add><input name=nome placeholder="Nome" required><input name=usuario placeholder="Usuário" required><input name=senha type=password placeholder="Senha (só Anciãos/Servos)"><select name=role>{% for k,v in ROLES.items() %}<option value="{{k}}" {{'selected' if k=='publicador'}}>{{v}}</option>{% endfor %}</select><button>Criar</button></form></div>
<div class=card><h2>Usuários</h2>{% for p in us %}<form method=post class=r style="margin-bottom:8px">{{H}}<input type=hidden name=act value=save><input type=hidden name=id value="{{p.id}}"><b style="min-width:150px">{{p.nome}}</b><span class=m>{{p.usuario}}</span><select name=role>{% for k,v in ROLES.items() %}<option value="{{k}}" {{'selected' if k==p.role}}>{{v}}</option>{% endfor %}</select><label><input type=checkbox name=ativo {{'checked' if p.ativo}}> ativo</label><input name=senha type=password placeholder="Nova senha"><button>Salvar</button></form>{% endfor %}</div>{% endblock %}""",
 "prog": PROG,
 "semanas": SEMANAS,
}
app.jinja_loader = DictLoader(TPL)

c = sqlite3.connect(DB); c.executescript(SCHEMA); c.commit(); c.close()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
