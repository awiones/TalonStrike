
import os
import shlex
import subprocess
from telegram import Update
from telegram.ext import ContextTypes

async def nmap(update: Update, context: ContextTypes.DEFAULT_TYPE):
    args = context.args
    if not args:
        help_message = (
            "🔍 <b>NMAP SCANNER</b> 🔍\n"
            "━━━━━━━━━━━━━━━━━━━━━\n\n"
            "<b>📋 Usage:</b>\n"
            "<code>/nmap &lt;target&gt; [options]</code>\n\n"
            "<b>🌟 Examples:</b>\n"
            "• <code>/nmap scanme.nmap.org</code>\n"
            "• <code>/nmap 192.168.1.1 -p 80,443</code>\n"
            "• <code>/nmap example.com -A -T4</code>\n\n"
            "<b>💡 Tips:</b>\n"
            "You can use any valid nmap parameters.\n"
            "Use <code>-p-</code> for all ports or <code>-sV</code> for service detection."
        )
        await update.message.reply_text(help_message, parse_mode="HTML")
        return
        
    # Build the nmap command
    nmap_cmd = ["nmap"] + args
    
    # Send a message indicating that scanning has started
    target = args[0]
    options = " ".join(args[1:]) if len(args) > 1 else "default options"
    
    progress_message = await update.message.reply_text(
        f"🔍 <b>NMAP SCAN IN PROGRESS</b> 🔍\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"🎯 <b>Target:</b> <code>{target}</code>\n"
        f"⚙️ <b>Options:</b> <code>{options}</code>\n\n"
        f"⏳ <b>Status:</b> Running...\n"
        f"⏱️ <b>Started at:</b> {update.message.date.strftime('%H:%M:%S')}\n\n"
        f"<i>Please wait, this scan might take a minute. Results will appear here when complete.</i>",
        parse_mode="HTML"
    )
    
    try:
        result = subprocess.run(nmap_cmd, capture_output=True, text=True, timeout=60)
        output = result.stdout or result.stderr
        
        # Format the output for better readability
        if output.strip():
            if len(output) > 3800:  # Reduced limit to allow for the formatting
                output = output[:3700] + "...\n(Output truncated due to length)"
            
            # Success message with formatted output
            completion_message = (
                f"✅ <b>NMAP SCAN COMPLETED</b> ✅\n"
                f"━━━━━━━━━━━━━━━━━━━━━\n\n"
                f"🎯 <b>Target:</b> <code>{target}</code>\n"
                f"⚙️ <b>Options:</b> <code>{options}</code>\n"
                f"🕒 <b>Duration:</b> Completed in a few seconds\n\n"
                f"📊 <b>RESULTS:</b>\n"
                f"<pre>{output}</pre>\n\n"
                f"🔐 <b>Scan by:</b> {update.effective_user.first_name}"
            )
        else:
            # Handle empty output
            completion_message = (
                f"⚠️ <b>NMAP SCAN COMPLETED</b> ⚠️\n"
                f"━━━━━━━━━━━━━━━━━━━━━\n\n"
                f"🎯 <b>Target:</b> <code>{target}</code>\n"
                f"⚙️ <b>Options:</b> <code>{options}</code>\n\n"
                f"📝 <b>Note:</b> The scan completed but returned no output.\n"
                f"This might indicate that the target is not reachable or the scan parameters need adjustment."
            )
        
        # Edit the original progress message with the results
        await progress_message.edit_text(completion_message, parse_mode="HTML")
        
    except subprocess.TimeoutExpired:
        # Handle timeout
        await progress_message.edit_text(
            f"⏱️ <b>SCAN TIMEOUT</b> ⏱️\n"
            f"━━━━━━━━━━━━━━━━━━━━━\n\n"
            f"🎯 <b>Target:</b> <code>{target}</code>\n"
            f"⚙️ <b>Options:</b> <code>{options}</code>\n\n"
            f"❗ The scan took too long and was terminated.\n"
            f"Try scanning fewer ports or using faster timing options (e.g., -T4).",
            parse_mode="HTML"
        )
    except Exception as e:
        # Update the progress message with the error
        await progress_message.edit_text(
            f"❌ <b>SCAN ERROR</b> ❌\n"
            f"━━━━━━━━━━━━━━━━━━━━━\n\n"
            f"🎯 <b>Target:</b> <code>{target}</code>\n"
            f"⚙️ <b>Options:</b> <code>{options}</code>\n\n"
            f"🔴 <b>Error:</b> {str(e)}\n\n"
            f"Try checking your command syntax or target availability.",
            parse_mode="HTML"
        )
