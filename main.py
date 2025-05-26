import os
from dotenv import load_dotenv
from telegram import Update, InputFile, BotCommand
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes, MessageHandler, filters
from flask import Flask, request
import threading
from modules.start import start
from modules.commands import commands
from modules.nmap import nmap
# Import the TelegramAIBot and bind its methods as handlers
from modules.startai import TelegramAIBot

# Explicitly specify the path to .env and debug existence
dotenv_path = os.path.join(os.path.dirname(__file__), ".env")
print(f"Resolved .env path: {dotenv_path}")
print(f".env exists: {os.path.exists(dotenv_path)}; readable: {os.access(dotenv_path, os.R_OK)}")

load_dotenv(dotenv_path)
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")

# Fallback: Manually load token if still missing
if not TELEGRAM_BOT_TOKEN:
    try:
        with open(dotenv_path) as f:
            for line in f:
                if line.startswith("TELEGRAM_BOT_TOKEN="):
                    TELEGRAM_BOT_TOKEN = line.strip().split("=", 1)[1]
                    print("Loaded TELEGRAM_BOT_TOKEN manually from file.")
                    break
    except Exception as e:
        print(f"Manual .env read failed: {e}")

# Debug: Print token status (masked)
if not TELEGRAM_BOT_TOKEN or not TELEGRAM_BOT_TOKEN.startswith("8"):
    raise ValueError(f"TELEGRAM_BOT_TOKEN is missing or invalid: {repr(TELEGRAM_BOT_TOKEN)}. Check your .env file and environment.")
print(f"Loaded TELEGRAM_BOT_TOKEN: {TELEGRAM_BOT_TOKEN[:8]}... (length: {len(TELEGRAM_BOT_TOKEN)})")

# Flask app for webscan
app = Flask(__name__)

@app.route("/webscan", methods=["GET"])
def webscan():
    return "Webscan endpoint active!", 200

async def set_bot_commands(application):
    import json
    commands_path = os.path.join(os.path.dirname(__file__), "modules", "commands.json")
    with open(commands_path, "r") as f:
        commands_list = json.load(f)
    bot_commands = [BotCommand(cmd["command"], cmd["description"]) for cmd in commands_list]
    await application.bot.set_my_commands(bot_commands)

def run_telegram_bot():
    app_builder = ApplicationBuilder().token(TELEGRAM_BOT_TOKEN)
    app = app_builder.build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("commands", commands))
    app.add_handler(CommandHandler("nmap", nmap))
    from modules.phone import phone
    app.add_handler(CommandHandler("phone", phone))
    from modules.dnslookup import dnslookup, reversedns
    app.add_handler(CommandHandler("dnslookup", dnslookup))
    app.add_handler(CommandHandler("reversedns", reversedns))
    from modules.whoislookup import whoislookup
    app.add_handler(CommandHandler("whoislookup", whoislookup))
    from modules.analyzeheader import analyzeheader
    app.add_handler(CommandHandler("analyzeheader", analyzeheader))
    from modules.doxing import doxing
    app.add_handler(CommandHandler("doxing", doxing))
    # --- AI Handlers ---
    ai_bot = TelegramAIBot()
    app.add_handler(CommandHandler("startai", ai_bot.start_ai))
    app.add_handler(CommandHandler("stopai", ai_bot.stop_ai))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, ai_bot.ai_message_handler))
    app.post_init = set_bot_commands
    app.run_polling()

def run_flask():
    app.run(host="0.0.0.0", port=5000)

if __name__ == "__main__":
    # Run Flask and Telegram bot in parallel
    flask_thread = threading.Thread(target=run_flask)
    flask_thread.start()
    run_telegram_bot()
