import os
from telegram import Update
from telegram.ext import ContextTypes

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # Send logo image with caption
    logo_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "modules", "images", "logo.jpeg")
    caption = (
        "🦅 <b>TalonStrike Bot</b>\n"
        "The real open-source OSINT\n\n"
        "✨ <b>Why TalonStrike?</b>\n"
        "• 100% free and open-source\n"
        "• No fake claims, no paywalls, no nonsense\n"
        "• Uses the same open-source tools as 'Scorpion Server'—but here, you don't pay for what is already free!\n"
        "• Transparent, honest, and for everyone\n\n"
        "💡 <b>Pro Tip:</b> Next time someone tries to sell you open-source tools, just send them this bot 😉\n\n"
        "<b>Commands:</b> Use /help to see what I can do."
    )
    with open(logo_path, "rb") as logo_file:
        await update.message.reply_photo(photo=logo_file, caption=caption, parse_mode="HTML")
