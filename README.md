# Ate Luningning Discord Bot

A friendly Filipino auntie Discord bot with AI capabilities powered by DeepSeek.

## Features

### AI Commands
- `!askluningning <question>` - Ask Ate Luningning anything (one-time questions)
- `!workstart` - Start a session-based chat (remembers conversation for 30 minutes)
- `!workend` - End your current work session

### Other Commands
- `!hello` - Get a warm greeting
- `!ping` - Check bot latency
- `!uptime` - See how long the bot has been running
- `!verse` - Get a random Bible verse
- `!horoscope <sign>` - Get daily horoscope for your zodiac sign
- `!calc <num1> <op> <num2>` - Simple calculator
- `!choose <option1>, <option2>, ...` - Let Ate Luningning choose for you
- `!roll <NdX>` - Roll dice (e.g., `!roll 1d6`, `!roll 2d10`)
- `!help` - Show all commands

### Admin Commands
- `!lock <command>` - Lock a command in the current channel
- `!unlock <command>` - Unlock a command in the current channel

## Session-Based Chat

The `!workstart` command starts a session-based chat where:
- The bot remembers your conversation context
- You can just talk normally (no need for `!` commands)
- Session automatically times out after 30 minutes of inactivity
- Use `!workend` to manually end the session

## Setup

1. Clone the repository
2. Install Go dependencies: `go mod download`
3. Create a `.env` file with the following:
   ```
   DISCORD_BOT_TOKEN=your_discord_bot_token
   DEEPSEEK_API_KEY=your_deepseek_api_key
   ADMIN_USER_IDS=user_id_1,user_id_2
   DEBUG=false
   ```
4. Build the bot: `go build -o bot`
5. Run: `./bot`

## Configuration

- `DISCORD_BOT_TOKEN`: Your Discord bot token from the Discord Developer Portal
- `DEEPSEEK_API_KEY`: Your DeepSeek API key (replaces Gemini)
- `ADMIN_USER_IDS`: Comma-separated list of Discord user IDs who can use admin commands
- `DEBUG`: Set to `true` for verbose logging

## Recent Updates

- **Replaced Gemini with DeepSeek**: All AI features now use DeepSeek API
- **Added session-based chat**: `!workstart` for conversations with memory
- **30-minute timeout**: Sessions automatically clear after inactivity
- **Context management**: Keeps last 20 messages for conversation continuity
- **Improved timeout handling**: 60-second timeout with automatic retries (3 attempts)
- **Better error messages**: User-friendly messages for timeout errors
- **Typing indicators**: Shows "Ate Luningning is typing..." while processing responses
