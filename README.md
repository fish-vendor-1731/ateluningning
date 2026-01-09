# Ate Luningning Discord Bot

A friendly Filipino auntie Discord bot with AI capabilities powered by DeepSeek.

## Features

### AI Commands
- `!askluningning <question>` - Ask Ate Luningning anything (one-time questions)
- `!chismis` - Start a session-based chat (remembers conversation for 30 minutes)
- `!yokona` - End your current work session

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

The `!chismis` command starts a session-based chat where:
- The bot remembers your conversation context
- You can just talk normally (no need for `!` commands)
- Session automatically times out after 30 minutes of inactivity
- Use `!yokona` to manually end the session

## Long Message Handling

Ate Luningning automatically handles long responses:

1. **Short messages** (< 2000 chars): Sent normally
2. **Moderate messages** (2000-6000 chars): Split into multiple Discord messages with proper rate limiting
3. **Long messages** (> 6000 chars): Sent as `ateluningning_response.txt` file attachment

### Rate Limit Protection
When splitting messages, the bot adds delays between parts to avoid Discord's rate limits:
- **200ms delay** before first part
- **800ms delay** between subsequent parts
- **Part numbering** ([Part 1/3], [Part 2/3], etc.) for clarity
- **No more cut-off messages** - all parts are delivered successfully

This ensures you always get the full response, even for very detailed answers!

## Attachment Support

Ate Luningning can now read and process `.txt` file attachments:

### Supported Scenarios:
1. **Session chat with attachments**: During `!chismis` sessions, upload `.txt` files for analysis
2. **`!askluningning` with attachments**: Ask questions about file content: `!askluningning summarize this file` + attachment
3. **File-only messages**: Send just a `.txt` file during a session for analysis

### File Processing Details:
- **File types**: Only `.txt` files are supported
- **Size limits**: Max 10MB file size, 10,000 character content limit
- **Security**: 30-second download timeout, proper User-Agent headers
- **Error handling**: Clear error messages for unsupported files or download issues

### Examples:
```
User: !chismis
Bot: Started a work session! You can now chat normally...
User: (uploads research.txt)
Bot: (analyzes the research document and responds)
```

```
User: !askluningning what are the key points in this document?
User: (attaches document.txt)
Bot: (reads the file and provides analysis)
```

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
- **Added session-based chat**: `!chismis` for conversations with memory
- **30-minute timeout**: Sessions automatically clear after inactivity
- **Context management**: Keeps last 20 messages for conversation continuity
- **Improved timeout handling**: 60-second timeout with automatic retries (3 attempts)
- **Better error messages**: User-friendly messages for timeout errors
- **Typing indicators**: Shows "Ate Luningning is typing..." while processing responses
- **Long message support**: Automatically splits long responses or sends as .txt files
- **Improved logging**: Better message logging with no blank messages in logs
- **Attachment support**: Bot can now read and process .txt file attachments
- **Rate limit handling**: Fixed message cutoff issues with proper delays between split messages
