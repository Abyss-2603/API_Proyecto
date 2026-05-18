from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, EmailStr
import psycopg2
from passlib.context import CryptContext
import requests
import os
from dotenv import load_dotenv
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random
import string
import re
import json

# Cargar variables de entorno del archivo .env
load_dotenv()

app = FastAPI()

# --- CONFIGURACIÓN ---
DATABASE_URL = os.getenv("DATABASE_URL")
MAIL_USERNAME = os.getenv("MAIL_USERNAME")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")

if not DATABASE_URL or not MAIL_PASSWORD:
    print("⚠️ ¡ERROR! No se han cargado las variables de entorno. Revisa tu archivo .env")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- MODELOS DE DATOS ---
class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class PasswordReset(BaseModel):
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    email: EmailStr
    code: str
    new_password: str

# Modelo para el correo de terror
class GameEmail(BaseModel):
    email: EmailStr
    nombre_jugador: str = "Jugador" 

# Modelo para guardar progreso
class GameProgress(BaseModel):
    user_id: int
    chapter: str
    decisions: dict

# --- CONEXIÓN DB ---
def get_db():
    try:
        return psycopg2.connect(DATABASE_URL)
    except Exception as e:
        print("Error conectando a DB:", e)
        raise HTTPException(status_code=500, detail="Error de Base de Datos")

# --- VERIFICACIÓN CON CÓDIGO ---
class VerifyCode(BaseModel):
    email: EmailStr
    code: str

@app.get("/api/health")
def health():
    return {"status": "ok"}

# Validación de contraseña
def validar_password(password: str):
    # Mínimo 5 caracteres
    if len(password) < 5:
        return False, "La contraseña debe tener al menos 5 caracteres."
    # Al menos una mayúscula
    if not any(c.isupper() for c in password):
        return False, "La contraseña debe tener al menos una letra mayúscula."
    # Al menos un número
    if not any(c.isdigit() for c in password):
        return False, "La contraseña debe tener al menos un número."
    # Al menos un símbolo (punto, coma, exclamación, etc.)
    if not re.search(r"[.[\],;!@#$%^&*()_+-=]", password):
        return False, "La contraseña debe tener al menos un símbolo (ej: . , ! @)."
    
    return True, "OK"

# REGISTRO
@app.post("/api/register")
def register(user: UserRegister):
    es_valida, mensaje = validar_password(user.password)
    if not es_valida:
        raise HTTPException(status_code=400, detail=mensaje)

    conn = get_db()
    cur = conn.cursor()
    hashed_pw = pwd_context.hash(user.password)
    try:
        cur.execute("INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s) RETURNING id", 
                    (user.username, user.email, hashed_pw))
        uid = cur.fetchone()[0]

        cur.execute("INSERT INTO game_state (user_id) VALUES (%s)", (uid,))

        # Enviar correo de bienvenida
        msg = MIMEMultipart("alternative")
        msg['Subject'] = "Bienvenido al ciclo"
        msg['From'] = f"Tu Subconsciente <{MAIL_USERNAME}>"
        msg['To'] = user.email
        
        html_content = f"""
        <html>
          <body style="background-color: #000000; color: #ff0000; font-family: 'Courier New', monospace; text-align: center; padding: 50px;">
            <h2 style="letter-spacing: 2px;">BIENVENIDO SEAS A ESTE NUEVO CICLO</h2>
            <p style="color: #cccccc;">
              Veo que decidiste empezar un nuevo ciclo indagando en los misterios que aguarda tu mente.
            </p>
            <p>
              Espero que disfrutes de esta experiencia aunque...un consejo, no te fíes ni de tu propia mente o tus pensamientos.
              AVISADO QUEDAS
            </p>
            <p style="font-size: 12px; color: #666;">
                Si no has sido tú quien se ha registrado, por favor, ignora este correo.
            </p>
          </body>
        </html>
        """
        
        part = MIMEText(html_content, "html")
        msg.attach(part)
        
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(MAIL_USERNAME, MAIL_PASSWORD)
        server.sendmail(MAIL_USERNAME, user.email, msg.as_string())
        server.quit()
        
        conn.commit()
        return {"msg": "Usuario registrado", "id": uid}
    except Exception as e:
        conn.rollback()
        print("Error registro:", e)
        raise HTTPException(status_code=400, detail="El usuario o email ya existe")
    finally:
        conn.close()

# LOGIN
# LOGIN MODIFICADO PARA DEVOLVER PARTIDA
@app.post("/api/login")
def login(user: UserLogin):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, password_hash, email FROM users WHERE username = %s", (user.username,))
    res = cur.fetchone()
    
    if not res or not pwd_context.verify(user.password, res[1]):
        conn.close()
        raise HTTPException(status_code=401, detail="Usuario o contraseña incorrectos")
    
    user_id = res[0]
    
    # se busca el progreso guardado
    cur.execute("SELECT current_chapter, decisions FROM game_state WHERE user_id = %s", (user_id,))
    estado = cur.fetchone()
    conn.close()

    progreso = {
        "capitulo": "prologo",
        "decisiones": {}
    }
    
    if estado:
        progreso["capitulo"] = estado[0] if estado[0] else "prologo"
        progreso["decisiones"] = estado[1] if estado[1] else {}

    return {
        "msg": "Login correcto", 
        "user_id": user_id,
        "username": user.username, 
        "email": res[2],
        "progreso": progreso
    }

# RECUPERAR CONTRASEÑA
@app.post("/api/forgot-password")
def forgot_password(req: PasswordReset):
    code = ''.join(random.choices(string.digits, k=6))
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute("UPDATE users SET reset_token = %s WHERE email = %s", (code, req.email))
    found = cur.rowcount > 0
    conn.commit()
    conn.close()
    
    if not found:
        raise HTTPException(status_code=404, detail="Correo no registrado en la base de datos.")
    if found:
        try:
            msg = MIMEMultipart("alternative")
            msg['Subject'] = "CÓDIGO DE ACCESO REQUERIDO"
            msg['From'] = f"Tu Subconsciente <{MAIL_USERNAME}>"
            msg['To'] = req.email
            
            html_content = f"""
            <html>
              <body style="background-color: #000000; color: #ff0000; font-family: 'Courier New', monospace; text-align: center; padding: 50px;">
                <h2 style="letter-spacing: 2px;">SOLICITUD DE RECUPERACIÓN</h2>
                <p style="color: #cccccc;">
                  Alguien (esperemos que tú) ha solicitado restablecer las credenciales.
                </p>
                <div style="border: 2px dashed #ff0000; padding: 20px; margin: 30px auto; width: fit-content; background-color: #1a0000;">
                    <span style="font-size: 40px; font-weight: bold; letter-spacing: 10px;">{code}</span>
                </div>
                <p style="font-size: 12px; color: #666;">
                  Este código se autodestruirá cuando lo uses.<br>
                  Si no has sido tú... ten cuidado.
                </p>
              </body>
            </html>
            """
            
            part = MIMEText(html_content, "html")
            msg.attach(part)
            
            server = smtplib.SMTP("smtp.gmail.com", 587)
            server.starttls()
            server.login(MAIL_USERNAME, MAIL_PASSWORD)
            server.sendmail(MAIL_USERNAME, req.email, msg.as_string())
            server.quit()
        except Exception as e:
            print(f"Error enviando mail: {e}")
            raise HTTPException(status_code=500, detail="Error enviando correo")

    return {"msg": "Código enviado."}

@app.post("/api/verify-code")
def verify_code(req: VerifyCode):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE email = %s AND reset_token = %s", (req.email, req.code))
    res = cur.fetchone()
    conn.close()
    
    if not res:
        raise HTTPException(status_code=400, detail="Código de validación incorrecto.")
    
    return {"msg": "Código válido"}

# RESET CONFIRM
@app.post("/api/reset-confirm")
def reset_confirm(req: PasswordResetConfirm):
    valido, msg = validar_password(req.new_password)
    if not valido:
        raise HTTPException(status_code=400, detail=msg)

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE email = %s AND reset_token = %s", (req.email, req.code))
    if not cur.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Código incorrecto")
    
    new_hash = pwd_context.hash(req.new_password)
    cur.execute("UPDATE users SET password_hash = %s, reset_token = NULL WHERE email = %s", 
                (new_hash, req.email))
    conn.commit()
    conn.close()
    return {"msg": "Contraseña actualizada"}

# Agarrar ip del usuario y mostrar su ciudad
@app.get("/api/horror-context")
def horror_context(request: Request):
    ip = request.headers.get("x-forwarded-for")
    if not ip or ip == "127.0.0.1": ip = "83.55.12.1"
    
    data = {"city": "Desconocido", "is_night": True}
    try:
        geo = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
        data["city"] = geo.get("city", "tu casa")
        data["region"] = geo.get("regionName", "algún lugar")
    except:
        pass
    return data

# Correo de terror (Mensaje final de Rocío)
@app.post("/api/creepy-email")
def send_creepy_email(req: GameEmail):
    
    msg = MIMEMultipart("alternative")
    msg['Subject'] = "Ayúdale." 
    msg['From'] = f"Rocío <{MAIL_USERNAME}>"
    msg['To'] = req.email

    html_content = f"""
    <html>
      <body style="background-color: #050505; color: #dddddd; font-family: 'Courier New', monospace; padding: 40px; text-align: left; line-height: 1.6;">
        
        <p>Soy Rocío.</p>
        
        <p>Él no quiere despertar por culpa de lo que me pasó. Sigue eligiendo mentir y ocultarse en ese mundo falso.</p>
        
        <p>Ahora llegará la última decisión.</p>
        
        <p>Por favor, <strong>{req.nombre_jugador}</strong>... haz que acepte la verdad.</p>
        <p>O... elige lo que quieras.</p>
        
        <br><br>
        <p style="color: #aa0000; font-style: italic;">No quiero que acabe igual...</p>
        
      </body>
    </html>
    """

    try:
        part = MIMEText(html_content, "html")
        msg.attach(part)

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(MAIL_USERNAME, MAIL_PASSWORD)
        server.sendmail(MAIL_USERNAME, req.email, msg.as_string())
        server.quit()
        
        return {"msg": "Correo de Rocío enviado"}
        
    except Exception as e:
        print(f"Error enviando correo de Rocío: {e}")
        return {"msg": "El correo falló, pero el juego continúa"}


# GUARDAR DECISIONES DEL JUGADOR
@app.post("/api/save-progress")
def save_progress(data: GameProgress):
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        query = """
        INSERT INTO game_state (user_id, current_chapter, decisions)
        VALUES (%s, %s, %s)
        ON CONFLICT (user_id) DO UPDATE SET
            current_chapter = EXCLUDED.current_chapter,
            decisions = EXCLUDED.decisions,
            last_updated = CURRENT_TIMESTAMP;
        """
        # Convertimos el diccionario 'new_decisions' a un string JSON real
        cursor.execute(query, (data.user_id, data.chapter, json.dumps(data.decisions)))
        conn.commit()
        conn.close()
        return {"status": "Progreso guardado"}
    except Exception as e:
        return {"error": str(e)}

# BORRAR CUENTA Y PARTIDA (Autodestrucción)
@app.delete("/api/delete-user/{user_id}")
def delete_user(user_id: int):
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Al borrar el usuario, el 'ON DELETE CASCADE' borra también su game_state
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
        conn.close()
        
        return {"msg": "Usuario y partida eliminados del ciclo."}
    except Exception as e:
        return {"error": str(e)}