import json
import os
from telegram import Update
from telegram.ext import ContextTypes

async def commands(update: Update, context: ContextTypes.DEFAULT_TYPE):
    commands_path = os.path.join(os.path.dirname(__file__), "commands.json")
    with open(commands_path, "r") as f:
        commands_list = json.load(f)
    text = "<b>Available Commands:</b>\n\n"
    for cmd in commands_list:
        text += f"/<b>{cmd['command']}</b> - {cmd['description']}\n"
    await update.message.reply_text(text, parse_mode="HTML")
