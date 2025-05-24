import os
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes
from flask import Flask, request
import threading

# Load environment variables
load_dotenv()
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")

# Flask app for webscan
app = Flask(__name__)

@app.route("/webscan", methods=["GET"])
def webscan():
    return "Webscan endpoint active!", 200

# Telegram bot setup
def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    return update.message.reply_text("Hello! TalonStrike bot is running.")

def run_telegram_bot():
    app_builder = ApplicationBuilder().token(TELEGRAM_BOT_TOKEN).build()
    app_builder.add_handler(CommandHandler("start", start))
    app_builder.run_polling()

def run_flask():
    app.run(host="0.0.0.0", port=5000)

if __name__ == "__main__":
    # Run Flask and Telegram bot in parallel
    flask_thread = threading.Thread(target=run_flask)
    flask_thread.start()
    run_telegram_bot()
