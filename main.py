import os
import threading
from dotenv import load_dotenv
from telegram import Update, InputFile, BotCommand
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes, MessageHandler, filters
from flask import Flask, request
from modules.start import start
from modules.commands import commands
from modules.nmap import nmap
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
    from modules.help import help_command
    app.add_handler(CommandHandler("help", help_command))
    app.post_init = set_bot_commands
    app.run_polling()

def run_flask():
    app.run(host="0.0.0.0", port=5000)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║                        TalonStrike CLI                       ║")
    print("║                     Bot Management System                    ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print()

def print_separator():
    print("─" * 64)

def show_token_tutorial():
    clear_screen()
    print_header()
    print("📖 TOKEN SETUP TUTORIAL")
    print_separator()
    print()
    print("🤖 TELEGRAM BOT TOKEN:")
    print("   1. Open Telegram and search for @BotFather")
    print("   2. Send /newbot command")
    print("   3. Follow the prompts to create your bot")
    print("   4. Copy the token (format: 123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11)")
    print()
    print("🐙 GITHUB TOKEN:")
    print("   1. Visit: https://github.com/settings/tokens")
    print("   2. Click 'Generate new token' (classic or fine-grained)")
    print("   3. Select required scopes:")
    print("      • 'repo' - Repository access")
    print("      • 'read:user' - User information access")
    print("   4. Copy and save the token (starts with 'ghp_...')")
    print()
    print_separator()
    input("Press Enter to continue...")

def get_token_input(token_type):
    while True:
        token = input(f"Enter your {token_type} Token: ").strip()
        if not token:
            print("❌ Token cannot be empty. Please try again.")
            continue
        if token_type == "Telegram Bot" and ':' not in token:
            print("❌ Invalid Telegram token format. Should contain ':'")
            continue
        elif token_type == "GitHub" and not token.startswith('ghp_'):
            print("❌ Invalid GitHub token format. Should start with 'ghp_'")
            continue
        return token

def auth_management_menu():
    while True:
        clear_screen()
        print_header()
        print("🔐 AUTHENTICATION MANAGEMENT")
        print_separator()
        print()
        print("1. Add/Update Tokens")
        print("2. Remove All Tokens")
        print("3. View Token Tutorial")
        print("0. Back to Main Menu")
        print()
        choice = input("Select an option [0-3]: ").strip()
        if choice == '1':
            clear_screen()
            print_header()
            print("🔑 TOKEN SETUP")
            print_separator()
            print()
            telegram_token = get_token_input("Telegram Bot")
            print("✓ Telegram token received")
            github_choice = input("\nDo you want to add a GitHub token? (y/N): ").strip().lower()
            github_token = None
            if github_choice == 'y':
                github_token = get_token_input("GitHub")
                print("✓ GitHub token received")
            print("\nUpdating configuration...")
            update_env_tokens(telegram_token, github_token)
            input("\nPress Enter to continue...")
        elif choice == '2':
            clear_screen()
            print_header()
            print("🗑️  REMOVE TOKENS")
            print_separator()
            print()
            remove_env_tokens()
            input("\nPress Enter to continue...")
        elif choice == '3':
            show_token_tutorial()
        elif choice == '0':
            break
        else:
            print("❌ Invalid option. Please select 0-3.")
            input("Press Enter to continue...")

def start_bot():
    clear_screen()
    print_header()
    print("🚀 STARTING BOT SERVICES")
    print_separator()
    print()
    print("Starting Flask server...")
    print("Starting Telegram bot...")
    print()
    print("✅ Bot services are now running!")
    print("📝 Check the logs above for any errors")
    print("🛑 Press Ctrl+C to stop the services")
    print()
    try:
        flask_thread = threading.Thread(target=run_flask)
        flask_thread.daemon = True
        flask_thread.start()
        run_telegram_bot()
    except KeyboardInterrupt:
        print("\n🛑 Services stopped by user")
    except Exception as e:
        print(f"❌ Error starting services: {e}")

def show_main_menu():
    clear_screen()
    print_header()
    print("📋 MAIN MENU")
    print_separator()
    print()
    print("1. 🔐 Authentication Management")
    print("2. 🚀 Start Bot Services")
    print("3. 📖 Token Setup Tutorial")
    print("0. 🚪 Exit Application")
    print()

def cli_menu():
    while True:
        show_main_menu()
        choice = input("Select an option [0-3]: ").strip()
        if choice == '1':
            auth_management_menu()
        elif choice == '2':
            start_bot()
            break
        elif choice == '3':
            show_token_tutorial()
        elif choice == '0':
            clear_screen()
            print_header()
            print("👋 Thank you for using TalonStrike!")
            print("   Have a great day!")
            print()
            break
        else:
            print("❌ Invalid option. Please select 0-3.")
            input("Press Enter to continue...")

def update_env_tokens(telegram_token, github_token=None):
    """Update .env with the given tokens. Sets both TELEGRAM_BOT_TOKEN and BOT_TOKEN to telegram_token."""
    lines = []
    found_telegram = found_bot = found_github = False
    if os.path.exists(dotenv_path):
        with open(dotenv_path, 'r') as f:
            for line in f:
                if line.startswith('TELEGRAM_BOT_TOKEN='):
                    lines.append(f'TELEGRAM_BOT_TOKEN={telegram_token}\n')
                    found_telegram = True
                elif line.startswith('BOT_TOKEN='):
                    lines.append(f'BOT_TOKEN={telegram_token}\n')
                    found_bot = True
                elif line.startswith('GITHUB_TOKEN=') and github_token is not None:
                    lines.append(f'GITHUB_TOKEN={github_token}\n')
                    found_github = True
                else:
                    lines.append(line)
    # Add missing keys
    if not found_telegram:
        lines.append(f'TELEGRAM_BOT_TOKEN={telegram_token}\n')
    if not found_bot:
        lines.append(f'BOT_TOKEN={telegram_token}\n')
    if github_token is not None and not found_github:
        lines.append(f'GITHUB_TOKEN={github_token}\n')
    with open(dotenv_path, 'w') as f:
        f.writelines(lines)
    print("Tokens updated in .env!")

def remove_env_tokens():
    """Remove TELEGRAM_BOT_TOKEN, BOT_TOKEN, and GITHUB_TOKEN from .env."""
    if not os.path.exists(dotenv_path):
        print(".env file not found.")
        return
    with open(dotenv_path, 'r') as f:
        lines = f.readlines()
    with open(dotenv_path, 'w') as f:
        for line in lines:
            if not (line.startswith('TELEGRAM_BOT_TOKEN=') or line.startswith('BOT_TOKEN=') or line.startswith('GITHUB_TOKEN=')):
                f.write(line)
    print("Tokens removed from .env!")

if __name__ == "__main__":
    try:
        cli_menu()
    except KeyboardInterrupt:
        print("\n\n👋 Application closed by user. Goodbye!")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        print("Please report this issue if it persists.")
