import os
import json
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters
from dotenv import load_dotenv

DATA_FILE = "data/reviewers.json"

# ---------- Utility functions ----------
# Load the file where the bot's persistent state (reviewers, pending, blocked) will be saved
def load_data():
    with open(DATA_FILE, "r") as f:
        return json.load(f)

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
    chat_id = update.effective_chat.id
    file = update.message.document

    data = load_data()

    # 1. Block check.
    if is_blocked(user.id, data):
        await update.message.reply_text("❌ Estás bloqueado y no puedes enviar writeups.")
        return

    # 2. Format check: only accepts PDF files.
    if not file.file_name.lower().endswith(".pdf"):
        await update.message.reply_text("Solo se aceptan archivos PDF.")
        return

    # 3. Assigns the next reviewer via rotation.
    reviewer_id = get_next_reviewer(data)
    if reviewer_id is None:
        await update.message.reply_text("No hay revisores configurados. Inténtalo más tarde.")
        return

    # 4. Save pending status: registers the request before sending it.
    data["pending"][str(user.id)] = {
        "username": user.username,
        "file_id": file.file_id,
        "reviewer": reviewer_id
    }
    save_data(data)

    # 5. Forward the file to the reviewer with action buttons.
    # TBD Add antivirus analysis or something similar
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
                    InlineKeyboardButton("❌ Rechazar", callback_data=f"reject:{user.id}"), # TBD It would be good to add a message explaining why it was rejected.
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
            await context.bot.add_chat_members(chat_id=group_id, user_ids=[user_id])
            await context.bot.send_message(
                chat_id=user_id,
                text="🎉 ¡Tu writeup ha sido aceptado! Ya formas parte de Hackiit."
            )
            await query.edit_message_caption(caption=f"✅ Writeup de @{user_info['username']} aceptado y añadido al grupo.")
        except Exception as e:
            await query.edit_message_caption(caption=f"⚠️ Error al añadir al usuario: {e}")

    # 3. Decision Logic: Reject.
    elif decision == "reject":
        await context.bot.send_message(
            chat_id=user_id,
            text="❌ Tu writeup ha sido rechazado, pero puedes intentarlo de nuevo cuando quieras." # TBD It would be good to add a message explaining why it was rejected.
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

# Handler for the /help command.
async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Comandos disponibles:\n"
        "/start - iniciar\n"
        "/userinfo - ver tu información de usuario\n"
        "/help - ayuda\n"
        "/unblock <user_id> - desbloquear usuario (solo revisores)"
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
    app.add_handler(MessageHandler(filters.Document.PDF, handle_document))
    app.add_handler(CallbackQueryHandler(handle_decision))

    print("Hackiit Bot is running...")
    app.run_polling()