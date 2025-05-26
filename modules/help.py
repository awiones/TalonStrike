import os
import json
from telegram import Update
from telegram.ext import ContextTypes
from html import escape

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    commands_path = os.path.join(os.path.dirname(__file__), "commands.json")
    with open(commands_path, "r") as f:
        commands_list = json.load(f)
    text = "<b>🦅 TalonStrike Bot Help</b>\n"
    text += "<i>The real open-source OSINT toolkit</i>\n"
    text += "<b>━━━━━━━━━━━━━━━━━━━━━━━</b>\n\n"
    text += "<b>📜 Available Commands:</b>\n"
    text += "<pre>"  # Start preformatted block for better alignment
    max_cmd_len = max(len(cmd['command']) for cmd in commands_list)
    for cmd in commands_list:
        cmd_name = escape(cmd['command']).ljust(max_cmd_len)
        text += f"/{cmd_name}  -  {escape(cmd['description'])}\n"
    text += "</pre>"
    text += ("\n\n<b>✨ Why TalonStrike?</b>\n"
             "• 100% free and open-source\n"
             "• No fake claims, no paywalls, no nonsense\n"
             "• Uses the same open-source tools as 'Scorpion Server'—but here, you don't pay for what is already free!\n"
             "• Transparent, honest, and for everyone\n")
    await update.message.reply_text(text, parse_mode="HTML")
