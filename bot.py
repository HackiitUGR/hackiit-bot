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
            files = { "file": (document.file_name, file_data, "application/pdf") }
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
        return {"reviewers": [], "pending": {}, "blocked": [], "next_index": 0}

    try:
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        print("⚠️ Advertencia: Archivo de datos vacío o corrupto. Inicializando.")
        return {"reviewers": [], "pending": {}, "blocked": [], "next_index": 0}

# Saves the current data to the JSON file.
def save_data(data):
    os.makedirs("data", exist_ok=True)
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=2)

# Gets the ID of the next reviewer using a round-robin rotation system.
def get_next_reviewer(data):
    reviewers = data.get("reviewers", [])
    if not reviewers:
        return None
    reviewer = reviewers[data["next_index"] % len(reviewers)]
    data["next_index"] = (data["next_index"] + 1) % len(reviewers)
    save_data(data)
    return reviewer

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

    # 2. Format check: only accepts PDF files.
    if not file.file_name.lower().endswith(".pdf") and file.mime_type != "application/pdf":
        await update.message.reply_text("Solo se aceptan archivos PDF.")
        return

    # 3. Check file with Virus Total
    file_id = file.file_id
    telegram_file = await context.bot.get_file(file_id)

    await update.message.reply_text("⏳ Analizando el archivo con VirusTotal. Esto puede tardar un momento...")

    check = await check_virus_total(file, telegram_file)
    if not check:
        # La función check_virus_total ya imprimió el error en la consola
        await update.message.reply_text("❌ Fichero sospechoso o la verificación de seguridad falló. Por favor, inténtalo con otro archivo.")
        return

    # 4. Assigns the next reviewer via rotation.
    reviewer_id = get_next_reviewer(data)
    if reviewer_id is None:
        await update.message.reply_text("No hay revisores configurados. Inténtalo más tarde.")
        return

    # 5. Save pending status: registers the request before sending it.
    data["pending"][str(user.id)] = {
        "username": user.username,
        "file_id": file.file_id,
        "reviewer": reviewer_id
    }
    save_data(data)

    # 6. Forward the file to the reviewer with action buttons.
    try:
        await context.bot.send_document(
            chat_id=reviewer_id,
            document=file.file_id,
            caption=(
                f"📄 Nuevo writeup recibido de @{user.username or user.full_name}\n"
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
        # Ajustamos el índice de rotación
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