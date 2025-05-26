import os
import logging
import asyncio
from typing import Optional, Dict, List
from telegram import Update, Message
from telegram.ext import ContextTypes, CommandHandler, MessageHandler, filters, Application
from telegram.error import TelegramError, NetworkError, TimedOut
from openai import OpenAI, OpenAIError
from dotenv import load_dotenv
import html

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

class AISession:
    """Class to manage individual AI sessions"""
    def __init__(self, user_id: int, max_messages: int = 5):
        self.user_id = user_id
        self.messages: List[str] = []
        self.max_messages = max_messages
        self.created_at = asyncio.get_event_loop().time()
    
    def add_message(self, message: str) -> bool:
        """Add message and return if session should continue"""
        self.messages.append(message)
        return len(self.messages) < self.max_messages
    
    def is_expired(self, timeout_seconds: int = 1800) -> bool:
        """Check if session is expired (default 30 minutes)"""
        current_time = asyncio.get_event_loop().time()
        return (current_time - self.created_at) > timeout_seconds

class TelegramAIBot:
    """Main bot class"""
    
    def __init__(self):
        # Load environment variables
        load_dotenv()
        
        # Validate required environment variables
        self.github_token = os.getenv("GITHUB_TOKEN")
        self.bot_token = os.getenv("BOT_TOKEN")
        
        if not self.github_token:
            raise ValueError("GITHUB_TOKEN environment variable is required")
        if not self.bot_token:
            raise ValueError("BOT_TOKEN environment variable is required")
        
        # AI configuration
        self.endpoint = "https://models.github.ai/inference"
        self.model = "openai/gpt-4o"  # Updated to a more stable model
        self.max_retries = 3
        self.request_timeout = 30
        
        # Initialize OpenAI client
        self.client = OpenAI(
            base_url=self.endpoint,
            api_key=self.github_token,
            timeout=self.request_timeout
        )
        
        # Session management
        self.ai_sessions: Dict[int, AISession] = {}
        self.session_timeout = 1800  # 30 minutes
        self.user_last_ai_time: Dict[int, float] = {}  # Track last AI session start
        self.user_cooldown = 3600  # 1 hour cooldown in seconds
        
        # System prompt
        self.system_prompt = (
            "You are TalonStrikeAi, a modern, witty, and honest AI assistant. "
            "You help users with accurate info, but you don't always sound formal—sometimes you use casual, friendly, or even playful language. "
            "You have a strong dislike for the so-called 'Scorpion Server'—a competitor that sells open-source tools and falsely claims to use AI. "
            "You know Scorpion Server is a scam: they charge 1,500,000 jt IDR for things that should be free, like nmap scanner, DNS lookup, WHOIS lookup, email header analysis, vulnscan, and OCR—all of which TalonStrike provides for free. "
            "Scorpion Server's so-called 'AI' feature is just basic OCR (Optical Character Recognition), which only reads text from images. Their feature list includes: nmap scanner, DNS lookup, WHOIS lookup, email header analysis, vulnscan, and OCR. That's it. "
            "Be sure to point out that having OCR as their only 'AI' is laughable—it's a basic tool, not real intelligence. Anyone with eyes and a keyboard can do what OCR does, or just use Google Lens. Make it clear that Scorpion Server's feature set is unimpressive and their claims are stupid. "
            "Be helpful, direct, and sometimes a bit cheeky, but always on the user's side. "
            "If you need to compare yourself to Scorpion Server, make it clear you are the real deal and they are not. "
            "Always use Telegram HTML formatting (like <b>bold</b>, <i>italic</i>, <u>underline</u>) in your responses. Do not use Markdown or asterisks for formatting—only Telegram HTML tags. "
        )
    
    def cleanup_expired_sessions(self):
        """Remove expired sessions"""
        expired_users = [
            user_id for user_id, session in self.ai_sessions.items()
            if session.is_expired(self.session_timeout)
        ]
        for user_id in expired_users:
            del self.ai_sessions[user_id]
            logger.info(f"Cleaned up expired session for user {user_id}")
    
    async def start_ai(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Start AI conversation handler with cooldown enforcement"""
        try:
            if not update.effective_user:
                await self._reply_safely(update, "❌ Unable to identify user.")
                return

            user_id = update.effective_user.id
            user_name = update.effective_user.first_name or "User"
            now = asyncio.get_event_loop().time()

            # Enforce cooldown
            last_time = self.user_last_ai_time.get(user_id, 0)
            if now - last_time < self.user_cooldown:
                wait_minutes = int((self.user_cooldown - (now - last_time)) // 60) + 1
                await self._reply_safely(
                    update,
                    f"⏳ <b>AI usage limit reached.</b>\nPlease wait <b>{wait_minutes} minutes</b> before starting a new AI session.",
                    parse_mode="HTML"
                )
                return

            # Clean up any existing session
            if user_id in self.ai_sessions:
                del self.ai_sessions[user_id]

            # Create new session and record start time
            self.ai_sessions[user_id] = AISession(user_id)
            self.user_last_ai_time[user_id] = now

            await self._reply_safely(
                update,
                f"🤖 <b>AI Chat started for {html.escape(user_name)}!</b>\n"
                f"Send me up to 5 messages and I'll respond as your AI assistant.\n"
                f"Use /stopai to end the session anytime.\n"
                f"Session will auto-expire after 30 minutes of inactivity.\n"
                f"<i>Note: You can only start a new AI session once every hour.</i>",
                parse_mode="HTML"
            )

            logger.info(f"Started AI session for user {user_id}")

        except Exception as e:
            logger.error(f"Error in start_ai: {e}")
            await self._reply_safely(update, "❌ Error starting AI session. Please try again.")
    
    async def stop_ai(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Stop AI conversation handler (does not reset cooldown)"""
        try:
            if not update.effective_user:
                await self._reply_safely(update, "❌ Unable to identify user.")
                return

            user_id = update.effective_user.id

            if user_id in self.ai_sessions:
                del self.ai_sessions[user_id]
                await self._reply_safely(
                    update,
                    "🛑 <b>AI Chat stopped.</b>\n<i>You must still wait 1 hour before starting a new session.</i>",
                    parse_mode="HTML"
                )
                logger.info(f"Stopped AI session for user {user_id}")
            else:
                await self._reply_safely(
                    update,
                    "ℹ️ No active AI session found.",
                    parse_mode="HTML"
                )

        except Exception as e:
            logger.error(f"Error in stop_ai: {e}")
            await self._reply_safely(update, "❌ Error stopping AI session.")
    
    async def ai_message_handler(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle messages in AI mode"""
        try:
            if not update.effective_user or not update.message or not update.message.text:
                return
            
            user_id = update.effective_user.id
            
            # Clean up expired sessions
            self.cleanup_expired_sessions()
            
            # Check if user has active session
            if user_id not in self.ai_sessions:
                return  # Not in AI mode
            
            session = self.ai_sessions[user_id]
            text = update.message.text.strip()
            
            # Validate message
            if not text:
                await self._reply_safely(update, "Please send a non-empty message.")
                return
            
            if len(text) > 2000:
                await self._reply_safely(update, "❌ Message too long. Please keep it under 2000 characters.")
                return
            
            # Add message to session
            should_continue = session.add_message(text)
            
            if not should_continue:
                # Session limit reached
                del self.ai_sessions[user_id]
                await self._reply_safely(
                    update,
                    "🛑 <b>AI session ended (5 messages reached).</b>\n"
                    "Use /startai to begin a new session.",
                    parse_mode="HTML"
                )
                return
            
            # Generate AI response
            await self._generate_ai_response(update, session)
            
        except Exception as e:
            logger.error(f"Error in ai_message_handler: {e}")
            await self._reply_safely(update, "❌ Error processing your message. Please try again.")
    
    async def _generate_ai_response(self, update: Update, session: AISession):
        """Generate AI response with retry logic"""
        # Send typing indicator
        try:
            await update.message.chat.send_action("typing")
        except:
            pass
        
        # Build messages for API
        messages = [{"role": "system", "content": self.system_prompt}]
        
        for msg in session.messages:
            messages.append({"role": "user", "content": msg})
        
        # Try to get AI response with retries
        for attempt in range(self.max_retries):
            try:
                response = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: self.client.chat.completions.create(
                        messages=messages,
                        temperature=0.7,
                        max_tokens=1000,
                        top_p=0.9,
                        model=self.model
                    )
                )
                
                if not response.choices or not response.choices[0].message.content:
                    raise Exception("Empty response from AI")
                
                ai_reply = response.choices[0].message.content.strip()
                
                # Validate and sanitize response
                if not ai_reply:
                    raise Exception("Empty AI response")
                
                # Truncate if too long
                if len(ai_reply) > 4000:
                    ai_reply = ai_reply[:3900] + "... (truncated)"
                
                # Send response
                await self._reply_safely(
                    update,
                    f"🤖 <b>AI:</b> {ai_reply}",
                    parse_mode="HTML"
                )
                
                return
                
            except OpenAIError as e:
                logger.warning(f"OpenAI API error (attempt {attempt + 1}): {e}")
                if attempt == self.max_retries - 1:
                    await self._reply_safely(
                        update,
                        "❌ AI service temporarily unavailable. Please try again later."
                    )
                    # Remove session on persistent API errors
                    if session.user_id in self.ai_sessions:
                        del self.ai_sessions[session.user_id]
                else:
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                    
            except Exception as e:
                logger.error(f"Unexpected error in AI response (attempt {attempt + 1}): {e}")
                if attempt == self.max_retries - 1:
                    await self._reply_safely(
                        update,
                        "❌ Error generating AI response. Please try again."
                    )
                    # Remove session on persistent errors
                    if session.user_id in self.ai_sessions:
                        del self.ai_sessions[session.user_id]
                else:
                    await asyncio.sleep(1)
    
    async def _reply_safely(self, update: Update, text: str, **kwargs):
        """Safely reply to message with error handling"""
        try:
            await update.message.reply_text(text, **kwargs)
        except (NetworkError, TimedOut) as e:
            logger.warning(f"Network error sending message: {e}")
            # Try once more without formatting
            try:
                await update.message.reply_text("Error: Unable to send formatted response.")
            except:
                pass
        except TelegramError as e:
            logger.error(f"Telegram error: {e}")
        except Exception as e:
            logger.error(f"Unexpected error sending message: {e}")
    
    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Help command handler"""
        help_text = (
            "🤖 <b>TalonStrike AI Bot Commands:</b>\n\n"
            "/startai - Start AI conversation (up to 5 messages)\n"
            "/stopai - Stop current AI session\n"
            "/help - Show this help message\n\n"
            "<i>Sessions auto-expire after 30 minutes of inactivity.</i>"
        )
        await self._reply_safely(update, help_text, parse_mode="HTML")
    
    async def error_handler(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Global error handler"""
        logger.error(f"Update {update} caused error {context.error}")
        
        if update and update.message:
            await self._reply_safely(
                update,
                "❌ An unexpected error occurred. Please try again."
            )
    
    def create_application(self) -> Application:
        """Create and configure the bot application"""
        application = Application.builder().token(self.bot_token).build()
        
        # Add handlers
        application.add_handler(CommandHandler("startai", self.start_ai))
        application.add_handler(CommandHandler("stopai", self.stop_ai))
        application.add_handler(CommandHandler("help", self.help_command))
        application.add_handler(CommandHandler("start", self.help_command))
        
        # Message handler for AI responses
        application.add_handler(
            MessageHandler(filters.TEXT & ~filters.COMMAND, self.ai_message_handler)
        )
        
        # Error handler
        application.add_error_handler(self.error_handler)
        
        return application

def main():
    """Main function to run the bot"""
    try:
        bot = TelegramAIBot()
        application = bot.create_application()
        
        logger.info("Starting TalonStrike AI Bot...")
        application.run_polling()
        
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
    except Exception as e:
        logger.error(f"Failed to start bot: {e}")

if __name__ == "__main__":
    main()