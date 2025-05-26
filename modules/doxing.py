import os
from telegram import Update
from telegram.ext import ContextTypes

async def doxing(update: Update, context: ContextTypes.DEFAULT_TYPE):
    image_path = os.path.join(os.path.dirname(__file__), "images", "getajoblilboy.jpg")
    caption = (
        "<b>Boo get a job lil boy</b>\n"
        "Stop act like hacker while you don't know shit.\n"
        "Your bug bounty is newbie level but you say you are high level hacker.\n"
        "You just using deface over and over, and also your israel leak police is re-leak 🤓👆"
    )
    with open(image_path, "rb") as img:
        await update.message.reply_photo(photo=img, caption=caption, parse_mode="HTML")
