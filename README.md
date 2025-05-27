<!-- filepath: /home/awion/TalonStrike/README.md -->
<p align="center">
  <img src="modules/images/logo.jpeg" alt="TalonStrike Logo" width="180"/>
</p>

# TalonStrike 🦅

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.7+-brightgreen.svg)](https://python.org)
[![Telegram Bot](https://img.shields.io/badge/Telegram-Bot-blue.svg)](https://core.telegram.org/bots)

A powerful and comprehensive Telegram bot designed for cybersecurity reconnaissance and network analysis. TalonStrike provides a wide range of tools for security professionals, researchers, and enthusiasts to perform various reconnaissance tasks directly through Telegram.

---

## 🚀 Features

### Core Functionality

- **Network Scanning** - Nmap integration for port scanning and service detection
- **DNS Lookup** - Domain name resolution and reverse DNS queries
- **WHOIS Lookup** - Domain registration and ownership information
- **Header Analysis** - HTTP header inspection and security analysis
- **Phone Number Lookup** - Telecommunications information gathering
- **OSINT Tools** - Open-source intelligence gathering capabilities
- **AI Integration** - Interactive AI assistant for guidance and automation

### Advanced Features

- **Multi-threading Support** - Concurrent bot and web services
- **Flask Web Interface** - Additional web-based scanning endpoints
- **Command Management** - Dynamic command registration and help system
- **Secure Token Management** - Protected API key storage and configuration
- **Interactive CLI** - User-friendly command-line interface for setup and management

## 📋 Prerequisites

- Python 3.7 or higher
- Telegram Bot Token (from [@BotFather](https://t.me/botfather))
- GitHub Token (optional, for enhanced features)

## 🔧 Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/your-username/TalonStrike.git
   cd TalonStrike
   ```

2. **Install required dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

3. **Set up your environment:**
   ```bash
   # Follow the interactive setup to configure your tokens.
   ```

## ⚙️ Configuration

### Telegram Bot Setup

1. Message [@BotFather](https://t.me/botfather) on Telegram
2. Create a new bot with `/newbot`
3. Save your bot token securely
4. Use the TalonStrike CLI to configure your tokens

## 🎯 Usage

### Starting the Bot

```bash
python main.py
```

### Available Commands

- `/start` - Initialize the bot and display welcome message
- `/commands` - List all available commands
- `/nmap <target>` - Perform network scanning
- `/dnslookup <domain>` - DNS resolution
- `/reversedns <ip>` - Reverse DNS lookup
- `/whoislookup <domain>` - WHOIS information
- `/analyzeheader <url>` - HTTP header analysis
- `/phone <number>` - Phone number information
- `/doxing <target>` - OSINT information gathering
- `/startai` - Activate AI assistant mode
- `/stopai` - Deactivate AI assistant
- `/help` - Display help information

## 🛡️ Security & Legal Notice

**⚠️ IMPORTANT DISCLAIMER:**

- This tool is intended for **educational purposes** and **authorized security testing** only
- Users are responsible for complying with all applicable laws and regulations
- Always obtain proper authorization before scanning or testing systems you do not own
- Misuse of this tool may violate local, state, national, or international laws
- The developers assume no liability for misuse or damages caused by this software

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Credits & Acknowledgments

This project is built using several excellent open-source libraries and tools:

### Network & Security Tools

- **[python-nmap](https://github.com/nmmapper/python3-nmap)** - Nmap integration

  - License: GPL-3.0
  - Enables network scanning capabilities

- **[python-whois](https://github.com/richardpenman/whois)** - WHOIS lookup functionality

  - License: MIT
  - Provides domain registration information

- **[Requests](https://github.com/psf/requests)** - HTTP library
  - License: Apache-2.0
  - Handles HTTP requests for various features

### Additional Tools

- **[Nmap](https://nmap.org/)** - Network discovery and security auditing
  - License: GPL-2.0
  - The underlying scanning engine (requires separate installation)

## 📞 Support

If you encounter any issues or have questions:

1. Check the [Issues](https://github.com/your-username/TalonStrike/issues) page
2. Create a new issue if your problem isn't already reported
3. Provide detailed information about your environment and the issue

---

**Made with ❤️**
