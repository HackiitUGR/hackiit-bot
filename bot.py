import asyncio
from dotenv import load_dotenv
import json
import os
import requests
import time

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters
from requests.exceptions import RequestException

VIRUS_TOTAL_URL = "https://www.virustotal.com/api/v3/files"
DATA_FILE = "data/reviewers.json"
VIRUS_TOTAL_REPORT_URL = "https://www.virustotal.com/api/v3/analyses/{0}" 
EXPECTED_MIME_TYPE = "application/pdf"


# ---------- Utility functions ----------

# Upload and check file with Virus Total
async def check_virus_total(document, telegram_file):
    # 1. Configure Headers and verify API Key
    vt_api_key = os.getenv("VIRUS_TOTAL_API_KEY")
    if not vt_api_key:
        print("❌ ERROR VT: Falta la variable VIRUS_TOTAL_API_KEY en .env.")
        return False

    headers = {
        "accept": "application/json",
        "x-apikey": vt_api_key,
    }

    file_path = f"/tmp/{document.file_name}"

    # 2. Download the file and upload it to VirusTotal
    print('VT LOG: Iniciando análisis de VirusTotal.')
    try:
        # Download the file to /tmp
        await telegram_file.download_to_drive(file_path)

        with open(file_path, 'rb') as file_data:
            files = { "file": (document.file_name, file_data, EXPECTED_MIME_TYPE) }
            print('VT LOG: Subiendo fichero a VirusTotal...')

            # Upload
            response = requests.post(VIRUS_TOTAL_URL, headers=headers, files=files)

            # Check the status code (It has to be 200 or 201)
            if response.status_code not in [200, 201]:
                print(f'❌ ERROR VT: Fallo en la subida. Código HTTP: {response.status_code}')
                print('❌ ERROR VT: Respuesta del servidor:', response.text)
                return False

            response_data = response.json()['data']
            print('VT LOG: Fichero enviado. ID de Análisis:', response_data.get('id'))
            analysis_url = response_data['links']['self']

    except RequestException as e:
        print(f"❌ ERROR VT: Fallo en la petición HTTP durante la subida: {e}")
        return False
    except Exception as e:
        print(f"❌ ERROR VT: Error inesperado en la subida o descarga: {e}")
        return False
    finally:
        # 3. Remove the temporary file
        if os.path.exists(file_path):
            os.remove(file_path)

    # 4. Wait for the analysis to complete
    for i in range(10): # Max of 10 attempts (100 seconds)
        await asyncio.sleep(10)
        print(f'VT LOG: Comprobando análisis... Intento {i+1}/10')

        try:
            # Get the report
            report_response = requests.get(analysis_url, headers=headers)

            if report_response.status_code != 200:
                print(f'❌ ERROR VT: Fallo al obtener el informe. Código HTTP: {report_response.status_code}')
                continue

            result = report_response.json()['data']
            status = result.get('attributes', {}).get('status')

            if status == 'completed':
                stats = result.get('attributes', {}).get('stats', {})
                print('VT LOG: Análisis COMPLETADO. Resultados de Stats:', stats)

                malicious_count = stats.get('malicious', -1)
                if malicious_count == 0:
                    return True
                else:
                    print(f'❌ ERROR VT: Fichero MALICIOSO detectado por {malicious_count} motores.')
                    return False

            elif status in ['queued', 'in_progress']:
                continue
            else:
                print(f"❌ ERROR VT: Estado desconocido/fallido: {status}. Finalizando.")
                return False

        except RequestException as e:
            print(f"❌ ERROR VT: Fallo en la petición HTTP durante el informe: {e}")
            await asyncio.sleep(5)
            continue

    print("❌ ERROR VT: Tiempo de espera agotado (100s) para el análisis.")
    return False

# Load the file where the bot's persistent state (reviewers, pending, blocked) will be saved
def load_data():
    if not os.path.exists(DATA_FILE) or os.path.getsize(DATA_FILE) == 0:
        # Initializing with 'user_assignments'
        return {"reviewers": [], "pending": {}, "blocked": [], "next_index": 0, "user_assignments": {}} 

    try:
        with open(DATA_FILE, "r") as f:
            data = json.load(f)
            # Ensure 'user_assignments' exists when loading
            if "user_assignments" not in data:
                data["user_assignments"] = {}
            return data
    except json.JSONDecodeError:
        print("⚠️ Advertencia: Archivo de datos vacío o corrupto. Inicializando.")
        # Initializing with 'user_assignments'
        return {"reviewers": [], "pending": {}, "blocked": [], "next_index": 0, "user_assignments": {}}

# Saves the current data to the JSON file.
def save_data(data):
    os.makedirs("data", exist_ok=True)
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=2)

# Gets the ID of the next reviewer using a round-robin rotation system (only for initial assignment).
def get_next_reviewer_round_robin(data):
    reviewers = data.get("reviewers", [])
    if not reviewers:
        return None

    reviewer = reviewers[data["next_index"] % len(reviewers)]
    data["next_index"] = (data["next_index"] + 1) % len(reviewers)
    save_data(data)
    return reviewer

# Gets the user's fixed reviewer or assigns a new one.
def get_user_reviewer(user_id, data):
    user_id_str = str(user_id)
    assignments = data.get("user_assignments", {})
    reviewers_list = data.get("reviewers", [])

    # 1. Check if the user already has an assigned reviewer and if they are still active
    if user_id_str in assignments:
        reviewer_id = assignments[user_id_str]

        if reviewer_id in reviewers_list:
            return reviewer_id # Return the existing fixed reviewer
        else:
            print(f"⚠️ Revisor {reviewer_id} asignado a usuario {user_id} ya no es revisor. Reasignando...")


    # 2. Assign a new one via round-robin
    new_reviewer_id = get_next_reviewer_round_robin(data)

    if new_reviewer_id is not None:
        # Save the new assignment
        data["user_assignments"][user_id_str] = new_reviewer_id
        save_data(data)
        return new_reviewer_id

    return None # No reviewers available

# Checks if a user is in the blocked list.
def is_blocked(user_id, data):
    return user_id in data.get("blocked", [])

# ---------- Handlers ----------

# Handler for the /start command: sends a welcome message and instructions.
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "👋 ¡Hola! Soy el bot de Hackiit.\n\n"
        "Si te gustaría ser parte del grupo, envíame tu *writeup en formato PDF* para poder revisarlo. En caso de ser aceptado, te añadiré al grupo. \n\n"
        "Para acceder a la plataforma de retos de iniciación, regístrate en: https://retos.hackiit.org\n\n",
        parse_mode="Markdown"
    )

# Handler for the /userinfo command (mainly for reviewers to know their ID).
async def userinfo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    await update.message.reply_text(
        f"Tu información:\n\n"
        f"Username: @{user.username or user.full_name}\n"
        f"User ID: {user.id}"
    )

# Handler for PDF documents: processes the writeup submission request.
async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    chat = update.effective_chat
    file = update.message.document

    # Avoid processing PDFs sent in the group.
    if chat.type != 'private':
        return

    data = load_data()

    # 1. Block check.
    if is_blocked(user.id, data):
        await update.message.reply_text("❌ Estás bloqueado y no puedes enviar writeups.")
        return

    # 2. Format check: Extension and MIME type
    if not file.file_name.lower().endswith(".pdf"):
        await update.message.reply_text("Solo se aceptan archivos PDF (extensión .pdf).")
        return

    if file.mime_type != EXPECTED_MIME_TYPE:
        print(f"⚠️ Archivo con MIME type incorrecto: {file.mime_type} (esperado: {EXPECTED_MIME_TYPE})")
        await update.message.reply_text(
            "❌ El formato de archivo no es válido (MIME type incorrecto)."
        )
        return

    # 3. Get file object for Virus Total
    file_id = file.file_id
    telegram_file = await context.bot.get_file(file_id)

    # 4. Check file with Virus Total
    await update.message.reply_text("⏳ Analizando el archivo con VirusTotal. Esto puede tardar un momento...")

    check = await check_virus_total(file, telegram_file) 

    if not check:
        await update.message.reply_text("❌ Fichero sospechoso o la verificación de seguridad falló. Por favor, inténtalo con otro archivo.")
        return

    # 5. Assigns the fixed reviewer.
    # We use the new function to get the fixed reviewer
    reviewer_id = get_user_reviewer(user.id, data) 

    if reviewer_id is None:
        await update.message.reply_text("No hay revisores configurados. Inténtalo más tarde.")
        return

    # 6. Save pending status: registers the request before sending it.
    # Reload data to get the fixed assignment if it was just created
    data = load_data() 
    data["pending"][str(user.id)] = {
        "username": user.username,
        "file_id": file.file_id,
        "reviewer": reviewer_id
    }
    save_data(data)

    # 7. Forward the file to the reviewer with action buttons.
    try:
        await context.bot.send_document(
            chat_id=reviewer_id,
            document=file.file_id,
            caption=(
                f"📄 Nuevo writeup recibido de @{user.username or user.full_name}\n"
                f"(Asignado: {user.username or user.full_name})"
            ),
            reply_markup=InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("✅ Aceptar", callback_data=f"accept:{user.id}"),
                    InlineKeyboardButton("❌ Rechazar", callback_data=f"reject:{user.id}"),
                    InlineKeyboardButton("🚫 Bloquear", callback_data=f"block:{user.id}")
                ]
            ])
        )
        await update.message.reply_text(
            "✅ Tu writeup ha sido enviado a revisión.\n\n"
            "Recibirás una respuesta cuando uno de nuestros revisores le eche un vistazo."
        )
    except Exception as e:
        await update.message.reply_text("Error al enviar el writeup a revisión.")
        print("Error:", e)

# Handler for buttons.
async def handle_decision(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = load_data()
    decision, user_id_str = query.data.split(":")
    user_id = int(user_id_str)
    pending = data.get("pending", {})

    # 1. Check: if the writeup is no longer pending, it is ignored.
    if str(user_id) not in pending:
        await query.edit_message_caption(caption="❌ Este writeup ya ha sido revisado o no existe.")
        return

    user_info = pending.pop(str(user_id))
    save_data(data)

    # 2. Decision Logic: Accept.
    if decision == "accept":
        try:
            group_id = int(os.getenv("GROUP_ID"))
            invite_link_obj = await context.bot.create_chat_invite_link(
                chat_id=group_id,
                member_limit=1
            )
            invite_link = invite_link_obj.invite_link
            await context.bot.send_message(
                chat_id=user_id,
                text=f"🎉 ¡Tu writeup ha sido aceptado! Ya formas parte de Hackiit. Invitación: {invite_link}"
            )
            await query.edit_message_caption(caption=f"✅ Writeup de @{user_info['username']} aceptado y añadido al grupo.")

        except Exception as e:
            await query.edit_message_caption(caption=f"⚠️ Error al añadir al usuario: {e}")
            print(f"Error al intentar añadir usuario: {e}")

    # 3. Decision Logic: Reject.
    elif decision == "reject":
        await context.bot.send_message(
            chat_id=user_id,
            text="❌ Tu writeup ha sido rechazado, pero puedes intentarlo de nuevo cuando quieras." 
        )
        await query.edit_message_caption(caption=f"❌ Writeup de @{user_info['username']} rechazado.")

    # 4. Decision Logic: Block.
    elif decision == "block":
        blocked_list = data.get("blocked", [])
        if user_id not in blocked_list:
            blocked_list.append(user_id)
            data["blocked"] = blocked_list
            save_data(data)
        await context.bot.send_message(
            chat_id=user_id,
            text="🚫 Has sido bloqueado y no podrás enviar writeups hasta que un administrador te desbloquee."
        )
        await query.edit_message_caption(
            caption=(
                f"🚫 @{user_info['username']} ha sido bloqueado.\n\n"
                f"Si en un futuro quieres desbloquearlo, usa /unblock {user_id}"
            )
        )

# Handler for the /unblock command: allows a reviewer to remove a user from the blocked list.
async def unblock_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    data = load_data()
    user = update.effective_user

    if user.id not in data.get("reviewers", []):
        await update.message.reply_text("❌ No tienes permiso para desbloquear usuarios.")
        return

    if len(context.args) != 1:
        await update.message.reply_text("Uso: /unblock <user_id>")
        return

    try:
        target_id = int(context.args[0])
    except ValueError:
        await update.message.reply_text("❌ El user_id debe ser un número.")
        return

    if target_id in data.get("blocked", []):
        data["blocked"].remove(target_id)
        save_data(data)
        await update.message.reply_text(f"✅ Usuario {target_id} desbloqueado.")
    else:
        await update.message.reply_text("❌ El usuario no estaba bloqueado.")

# Handler for the /add_reviewer command: allows adding a new reviewer.
async def add_reviewer_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    data = load_data()
    user = update.effective_user

    if user.id not in data.get("reviewers", []):
        await update.message.reply_text("❌ No tienes permiso para añadir revisores.")
        return

    if len(context.args) != 1:
        await update.message.reply_text("Uso: /add_reviewer <user_id>")
        return

    try:
        new_reviewer_id = int(context.args[0])
    except ValueError:
        await update.message.reply_text("❌ El user_id debe ser un número.")
        return

    if new_reviewer_id not in data.get("reviewers", []):
        data["reviewers"].append(new_reviewer_id)
        save_data(data)
        await update.message.reply_text(f"✅ Usuario {new_reviewer_id} añadido como revisor.")
    else:
        await update.message.reply_text("❌ El usuario ya es revisor.")

# Handler for the /remove_reviewer command: allows removing a reviewer.
async def remove_reviewer_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    data = load_data()
    user = update.effective_user

    if user.id not in data.get("reviewers", []):
        await update.message.reply_text("❌ No tienes permiso para eliminar revisores.")
        return

    if len(context.args) != 1:
        await update.message.reply_text("Uso: /remove_reviewer <user_id>")
        return

    try:
        reviewer_id = int(context.args[0])
    except ValueError:
        await update.message.reply_text("❌ El user_id debe ser un número.")
        return

    if reviewer_id == user.id:
        await update.message.reply_text("❌ No puedes eliminarte a ti mismo como revisor.")
        return

    if reviewer_id in data.get("reviewers", []):
        data["reviewers"].remove(reviewer_id)
        # Adjust rotation index
        if data["reviewers"]:
            data["next_index"] = data["next_index"] % len(data["reviewers"])
        else:
            data["next_index"] = 0

        save_data(data)
        await update.message.reply_text(f"✅ Usuario {reviewer_id} eliminado como revisor.")
    else:
        await update.message.reply_text("❌ El usuario no es revisor.")

# Handler for the /help command.
async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Comandos disponibles:\n"
        "/start - iniciar\n"
        "/userinfo - ver tu información de usuario\n"
        "/help - ayuda\n"
        "/unblock <user_id> - desbloquear usuario (solo revisores)\n"
        "/add_reviewer <user_id> - añadir revisor (solo revisores)\n"
        "/remove_reviewer <user_id> - eliminar revisor (solo revisores)"
    )

# ---------- Main ----------
if __name__ == "__main__":
    load_dotenv()
    token = os.getenv("TELEGRAM_TOKEN")
    if not token:
        raise SystemExit("Error: falta TELEGRAM_TOKEN en .env")

    app = ApplicationBuilder().token(token).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("userinfo", userinfo))
    app.add_handler(CommandHandler("unblock", unblock_command))
    app.add_handler(CommandHandler("add_reviewer", add_reviewer_command))
    app.add_handler(CommandHandler("remove_reviewer", remove_reviewer_command))
    app.add_handler(MessageHandler(filters.Document.PDF, handle_document))
    app.add_handler(CallbackQueryHandler(handle_decision))

    print("Hackiit Bot is running...")
    app.run_polling()