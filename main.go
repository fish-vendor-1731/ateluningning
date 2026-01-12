package main

import (
	"bytes"
	"database/sql" // Reintroduced for persistence (for command locking)
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"github.com/bwmarrin/discordgo"
	"github.com/joho/godotenv"
	_ "github.com/mattn/go-sqlite3" // For SQLite driver
)

// Configuration constants
const (
	Prefix             = "!"
	BibleAPIURL        = "https://bible-api.com/data/web/random"
	// HoroscopeAPIHost and HoroscopeAPIURL are removed as Gemini will handle horoscopes now
	DeepSeekAPIHost    = "api.deepseek.com"
	DeepSeekAPIPath    = "/chat/completions"
	DefaultDeepSeekModel = "deepseek-chat" // Using 'deepseek-chat' as default
	RequestTimeout     = 60 * time.Second // Increased from 20 to 60 seconds for DeepSeek
	EnvFileName        = ".env"
	DatabaseFile       = "./bot.db" // Database file name (for command locking)
	AteLuningningAICommand = "askluningning" // Consistent name for the AI command
	WorkStartCommand   = "chismis" // New command for session-based chat
	SessionTimeout     = 30 * time.Minute // 30 minutes timeout for sessions
)

// AppConfig holds application-wide configuration
type AppConfig struct {
	DiscordToken      string
	// RapidAPIHoroscopeKey is removed
	DeepSeekAPIKey    string
	AdminUserIDs      []string
	Debug             bool
}

// Session represents a user's chat session
type Session struct {
	UserID      string
	ChannelID   string
	Messages    []DeepSeekMessage // Conversation history
	LastActive  time.Time
	IsActive    bool
}

// SessionManager manages all active sessions
type SessionManager struct {
	sessions map[string]*Session // key: userID+channelID
	mu       sync.RWMutex
}

// Global variables
var appConfig *AppConfig
var startTime time.Time
var db *sql.DB // Database connection
var sessionManager *SessionManager

// --- Ate Luningning Persona Constants ---
const (
	AteLuningningName        = "Ate Luningning"
	AteLuningningGreeting    = "Oh, hello there, my dear!! Ate Luningning is here. "
	AteLuningningErrorPrefix = "Oh dear, something went wrong in Ate Luningning's kitchen! "
)

// BibleVerse represents the structured data from the Bible API
type BibleVerse struct {
	Translation map[string]interface{} `json:"translation"`
	RandomVerse map[string]interface{} `json:"random_verse"`
}

// HoroscopeData represents the structured response (now expected from Gemini)
type HoroscopeData struct {
	// Status field is now not applicable from Gemini's direct output, but we keep it boolean for consistency
	// We'll set it to true if parsing succeeds.
	Status          bool   `json:"status"` // Will be set to true if JSON parsing succeeds
	Prediction      string `json:"prediction"` // Main horoscope text
	Number          string `json:"number"`
	Color           string `json:"color"`
	Strength        string `json:"strength"`
	Weakness        string `json:"weakness"`
	LoveCompatibility string `json:"love_compatibility"`
	ZodiacSign      string `json:"zodiacSign"` // This will be passed to Gemini in the prompt
}

// --- DeepSeek API Structs ---
type DeepSeekMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type DeepSeekChatRequest struct {
	Model    string            `json:"model"`
	Messages []DeepSeekMessage `json:"messages"`
	Stream   bool              `json:"stream"`
}

type DeepSeekChoice struct {
	Message DeepSeekMessage `json:"message"`
}

type DeepSeekChatResponse struct {
	Choices []DeepSeekChoice `json:"choices"`
}
// --- End DeepSeek API Structs ---

// A map to quickly check for valid zodiac signs
var validSigns = map[string]bool{
	"aries":       true, "taurus":      true, "gemini":      true,
	"cancer":      true, "leo":         true, "virgo":       true,
	"libra":       true, "scorpio":     true, "sagittarius": true,
	"capricorn":   true, "aquarius":    true, "pisces":      true,
}

// CapitalizeFirstLetter capitalizes the first letter of a string.
func CapitalizeFirstLetter(s string) string {
	if s == "" {
		return ""
	}
	r := []rune(s)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}

// loadConfiguration handles loading and validating application configuration
func loadConfiguration() (*AppConfig, error) {
	err := godotenv.Load(EnvFileName)
	if err != nil {
		return nil, fmt.Errorf("error loading %s file: %w", EnvFileName, err)
	}

	config := &AppConfig{
		DiscordToken:      os.Getenv("DISCORD_BOT_TOKEN"),
		DeepSeekAPIKey:    os.Getenv("DEEPSEEK_API_KEY"),
		Debug:             os.Getenv("DEBUG") == "true",
	}

	// Parse admin user IDs
	adminIDsStr := os.Getenv("ADMIN_USER_IDS")
	if adminIDsStr != "" {
		config.AdminUserIDs = strings.Split(adminIDsStr, ",")
		for i, id := range config.AdminUserIDs {
			config.AdminUserIDs[i] = strings.TrimSpace(id)
		}
	} else {
		log.Printf("WARNING: ADMIN_USER_IDS is not set in %s. Lock/unlock commands will not be available.", EnvFileName)
	}

	if config.DiscordToken == "" {
		return nil, fmt.Errorf("DISCORD_BOT_TOKEN is required in %s", EnvFileName)
	}
	if config.DeepSeekAPIKey == "" {
		log.Printf("WARNING: DEEPSEEK_API_KEY is not set in %s. `!%s` and `!chismis` commands will not work.", EnvFileName, AteLuningningAICommand)
	}

	return config, nil
}

// configureLogging sets up logging based on configuration
func configureLogging(debug bool) {
	if debug {
		log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile | log.Lmicroseconds)
	} else {
		log.SetFlags(log.Ldate | log.Ltime)
	}
}

// readyHandler logs when the bot successfully connects to Discord and sets start time
func readyHandler(s *discordgo.Session, event *discordgo.Ready) {
	log.Printf("Bot connected as %s#%s (ID: %s)", s.State.User.Username, s.State.User.Discriminator, s.State.User.ID)
	for _, guild := range s.State.Guilds {
		log.Printf("Connected to guild: %s (ID: %s)", guild.Name, guild.ID)
	}
	startTime = time.Now()
	rand.Seed(time.Now().UnixNano())
}

// SafeSend sends a message to the specified channel with error handling
func SafeSend(s *discordgo.Session, channelID, content string) {
	if content == "" {
		log.Printf("WARNING: Attempted to send empty message to channel %s", channelID)
		return
	}

	// Log the message being sent (truncate if too long for logs)
	logContent := content
	if len(logContent) > 100 {
		logContent = logContent[:100] + "..."
	}
	log.Printf("Sending message to channel %s: %s", channelID, logContent)

	_, err := s.ChannelMessageSend(channelID, content)
	if err != nil {
		log.Printf("Error sending message to channel %s: %v", channelID, err)
	}
}

// SafeSendEmbed sends an embedded message with error handling
func SafeSendEmbed(s *discordgo.Session, channelID string, embed *discordgo.MessageEmbed) {
	if embed == nil {
		log.Printf("WARNING: Attempted to send nil embed to channel %s", channelID)
		return
	}

	// Log the embed being sent
	embedTitle := "No title"
	if embed.Title != "" {
		embedTitle = embed.Title
	}
	log.Printf("Sending embed to channel %s: %s", channelID, embedTitle)

	_, err := s.ChannelMessageSendEmbed(channelID, embed)
	if err != nil {
		log.Printf("Embed send error in channel %s: %v", channelID, err)
	}
}

// getBibleVerse fetches a random Bible verse with robust error handling
func getBibleVerse() (*BibleVerse, error) {
	client := &http.Client{
		Timeout: RequestTimeout,
	}

	if appConfig.Debug {
		log.Printf("DEBUG: Fetching Bible verse from: %s", BibleAPIURL)
	}

	resp, err := client.Get(BibleAPIURL)
	if err != nil {
		return nil, fmt.Errorf("bible verse API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("bible verse API returned status: %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024))
	if err != nil {
		return nil, fmt.Errorf("error reading API response: %w", err)
	}

	var verse BibleVerse
	if err := json.Unmarshal(body, &verse); err != nil {
		return nil, fmt.Errorf("failed to parse verse data: %w", err)
	}

	return &verse, nil
}

// createVerseEmbed generates a rich, informative Discord embed
func createVerseEmbed(verse *BibleVerse) *discordgo.MessageEmbed {
	var builder strings.Builder

	builder.WriteString("**Translation Details:**\n")
	for key, value := range verse.Translation {
		builder.WriteString(fmt.Sprintf("- %s: %v\n", key, value))
	}

	builder.WriteString("\n**Random Verse:**\n")
	for key, value := range verse.RandomVerse {
		builder.WriteString(fmt.Sprintf("- %s: %v\n", key, value))
	}

	return &discordgo.MessageEmbed{
		Title:       "Daily Bible Verse 📖",
		Description: builder.String(),
		Color:       0x3498db,
		Timestamp:   time.Now().Format(time.RFC3339),
	}
}

// getDeepSeekResponse sends a prompt to the DeepSeek API and returns the generated text.
// This is a generic function that can be used for any DeepSeek prompt.
func getDeepSeekResponse(prompt, apiKey, modelName string) (string, error) {
	if apiKey == "" {
		return "", fmt.Errorf("DeepSeek API key is not configured")
	}

	client := &http.Client{
		Timeout: RequestTimeout,
	}

	fullURL := fmt.Sprintf("https://%s%s", DeepSeekAPIHost, DeepSeekAPIPath)

	requestBody := DeepSeekChatRequest{
		Model: modelName,
		Messages: []DeepSeekMessage{
			{
				Role:    "user",
				Content: prompt,
			},
		},
		Stream: false,
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal DeepSeek request body: %w", err)
	}

	if appConfig.Debug {
		log.Printf("DEBUG: Sending DeepSeek API request to: %s", fullURL)
		log.Printf("DEBUG: DeepSeek Request Payload: %s", string(jsonBody))
	}

	req, err := http.NewRequest("POST", fullURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", fmt.Errorf("failed to create DeepSeek API request: %w", err)
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", apiKey))

	// Try up to 3 times with exponential backoff
	var resp *http.Response
	maxRetries := 3
	for i := 0; i < maxRetries; i++ {
		resp, err = client.Do(req)
		if err == nil {
			break
		}

		// If it's a timeout error and we have retries left, wait and retry
		errLower := strings.ToLower(err.Error())
		if strings.Contains(errLower, "timeout") || strings.Contains(errLower, "deadline") || strings.Contains(errLower, "canceled") {
			if i < maxRetries-1 {
				waitTime := time.Duration(i+1) * 2 * time.Second // Exponential backoff: 2s, 4s, 6s
				log.Printf("DeepSeek API timeout (attempt %d/%d), retrying in %v...", i+1, maxRetries, waitTime)
				time.Sleep(waitTime)
				continue
			}
		}
		// For other errors, break immediately
		break
	}

	if err != nil {
		return "", fmt.Errorf("DeepSeek API request failed after %d attempts: %w", maxRetries, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 50*1024))
	if err != nil {
		return "", fmt.Errorf("error reading DeepSeek API response: %w", err)
	}

	if appConfig.Debug {
		log.Printf("DEBUG: DeepSeek Response Status: %d", resp.StatusCode)
		log.Printf("DEBUG: DeepSeek Response Body: %s", string(body))
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("DeepSeek API returned status: %d, body: %s", resp.StatusCode, string(body))
	}

	var deepSeekResponse DeepSeekChatResponse
	if err := json.Unmarshal(body, &deepSeekResponse); err != nil {
		return "", fmt.Errorf("failed to parse DeepSeek API response: %w", err)
	}

	if len(deepSeekResponse.Choices) == 0 {
		return "", fmt.Errorf("DeepSeek API returned no choices")
	}

	return deepSeekResponse.Choices[0].Message.Content, nil
}

// getDeepSeekHoroscope fetches horoscope data from DeepSeek API, asking for structured output.
func getDeepSeekHoroscope(sign string, apiKey, modelName string) (*HoroscopeData, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("DeepSeek API key is not configured for horoscope")
	}

	lowerSign := strings.ToLower(sign)
	if !validSigns[lowerSign] {
		return nil, fmt.Errorf("invalid zodiac sign: %s", sign)
	}

	currentDate := time.Now().Format("January 2, 2006")

	// Prompt crafted to request JSON output matching HoroscopeData struct
	prompt := fmt.Sprintf(`Generate a daily horoscope for %s for today, %s. Provide the response in JSON format only, with the following keys:
- "status": boolean, always true if content is generated
- "zodiacSign": string, the zodiac sign (e.g., "Leo")
- "prediction": string, the main horoscope text
- "love_compatibility": string, love related insights
- "strength": string, strengths for the sign
- "weakness": string, weaknesses for the sign
- "color": string, lucky color(s)
- "number": string, lucky number(s)

Do not include any other text, markdown, or explanation outside the JSON object. Example:
{"status": true, "zodiacSign": "Leo", "prediction": "Your day will be productive...", "love_compatibility": "Compatible with...", "strength": "Courageous", "weakness": "Arrogant", "color": "Gold", "number": "1, 5"}`,
	CapitalizeFirstLetter(lowerSign), currentDate)

	rawDeepSeekResponse, err := getDeepSeekResponse(prompt, apiKey, modelName)
	if err != nil {
		return nil, fmt.Errorf("error getting raw DeepSeek response for horoscope: %w", err)
	}

	var horoscopeData HoroscopeData
	// Attempt to unmarshal the response. DeepSeek might not always provide perfect JSON.
	err = json.Unmarshal([]byte(rawDeepSeekResponse), &horoscopeData)
	if err != nil {
		// If unmarshaling fails, it means DeepSeek didn't return valid JSON.
		// Log the raw response to debug DeepSeek's output.
		if appConfig.Debug {
			log.Printf("DEBUG: Failed to unmarshal DeepSeek horoscope response. Raw response: %s", rawDeepSeekResponse)
		}
		// Return the raw response in the error for the user to see what went wrong.
		return nil, fmt.Errorf("DeepSeek did not return horoscope in expected JSON format. Please try again. Raw output: ```json\n%s\n``` (check bot logs for full details)", rawDeepSeekResponse)
	}

	horoscopeData.Status = true // Assuming if parsing succeeds, the status is true
	if horoscopeData.ZodiacSign == "" {
		horoscopeData.ZodiacSign = CapitalizeFirstLetter(lowerSign) // Ensure sign is set
	}

	return &horoscopeData, nil
}


// createHoroscopeEmbed generates a Discord embed for horoscope data
func createHoroscopeEmbed(data *HoroscopeData) *discordgo.MessageEmbed {
	displaySign := CapitalizeFirstLetter(data.ZodiacSign)

	embed := &discordgo.MessageEmbed{
		Title:       fmt.Sprintf("%s Daily Horoscope 🌟", displaySign),
		Description: data.Prediction, // Use 'Prediction' for the main text
		Color:       0xFEE75C, // A nice yellow/gold color
		Fields: []*discordgo.MessageEmbedField{
			{
				Name:   "Love Compatibility",
				Value:  data.LoveCompatibility,
				Inline: false, // Make these wider for better readability
			},
			{
				Name:   "Strengths",
				Value:  data.Strength,
				Inline: false,
			},
			{
				Name:   "Weaknesses",
				Value:  data.Weakness,
				Inline: false,
			},
			{
				Name:   "Lucky Color",
				Value:  data.Color,
				Inline: true,
			},
			{
				Name:   "Lucky Number",
				Value:  data.Number, // 'number' is a string now
				Inline: true,
			},
		},
		Timestamp: time.Now().Format(time.RFC3339),
		Footer: &discordgo.MessageEmbedFooter{
			Text: "Horoscope by Ate Luningning's Smart Brain (Daily Forecast)", // Updated source
		},
	}
	return embed
}

// --- Assistant Functionalities ---

// formatDuration formats time.Duration into a human-readable string.
func formatDuration(d time.Duration) string {
	s := int(d.Seconds())
	days := s / (24 * 3600)
	s %= (24 * 3600)
	hours := s / 3600
	s %= 3600
	minutes := s / 60
	seconds := s % 60

	parts := []string{}
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%d days", days))
	}
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%d hours", hours))
	}
	if minutes > 0 {
		parts = append(parts, fmt.Sprintf("%d minutes", minutes))
	}
	if seconds > 0 || len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%d seconds", seconds))
	}

	return strings.Join(parts, ", ")
}

// --- Session Management Functions ---

// NewSessionManager creates a new session manager
func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*Session),
	}
}

// getSessionKey generates a unique key for a user-channel combination
func getSessionKey(userID, channelID string) string {
	return userID + ":" + channelID
}

// StartSession starts a new session for a user in a channel
func (sm *SessionManager) StartSession(userID, channelID string) *Session {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	key := getSessionKey(userID, channelID)

	// Check if session already exists
	if session, exists := sm.sessions[key]; exists {
		session.LastActive = time.Now()
		session.IsActive = true
		return session
	}

	// Create new session
	session := &Session{
		UserID:     userID,
		ChannelID:  channelID,
		Messages:   make([]DeepSeekMessage, 0),
		LastActive: time.Now(),
		IsActive:   true,
	}

	sm.sessions[key] = session
	return session
}

// GetSession retrieves a session for a user in a channel
func (sm *SessionManager) GetSession(userID, channelID string) (*Session, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	key := getSessionKey(userID, channelID)
	session, exists := sm.sessions[key]
	if !exists || !session.IsActive {
		return nil, false
	}

	// Update last active time
	session.LastActive = time.Now()
	return session, true
}

// EndSession ends a session for a user in a channel
func (sm *SessionManager) EndSession(userID, channelID string) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	key := getSessionKey(userID, channelID)
	if session, exists := sm.sessions[key]; exists {
		session.IsActive = false
		session.Messages = make([]DeepSeekMessage, 0) // Clear messages
		return true
	}
	return false
}

// AddMessage adds a message to a session's conversation history
func (sm *SessionManager) AddMessage(userID, channelID string, role, content string) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	key := getSessionKey(userID, channelID)
	session, exists := sm.sessions[key]
	if !exists || !session.IsActive {
		return false
	}

	session.Messages = append(session.Messages, DeepSeekMessage{
		Role:    role,
		Content: content,
	})
	session.LastActive = time.Now()

	// Keep only last 20 messages to prevent context from getting too large
	if len(session.Messages) > 20 {
		session.Messages = session.Messages[len(session.Messages)-20:]
	}

	return true
}

// CleanupInactiveSessions removes sessions that have been inactive for too long
func (sm *SessionManager) CleanupInactiveSessions() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()
	for _, session := range sm.sessions {
		if session.IsActive && now.Sub(session.LastActive) > SessionTimeout {
			session.IsActive = false
			session.Messages = make([]DeepSeekMessage, 0)
			log.Printf("Session timeout for user %s in channel %s", session.UserID, session.ChannelID)
		}
	}
}

// handleSessionChat handles messages in an active session
func handleSessionChat(s *discordgo.Session, m *discordgo.MessageCreate, session *Session) {
	// Process message content and attachments
	messageContent := m.Content
	hasAttachments := len(m.Attachments) > 0

	// If there are attachments, process them
	if hasAttachments {
		for _, attachment := range m.Attachments {
			textContent, err := processAttachment(attachment)
			if err != nil {
				log.Printf("Error processing attachment %s: %v", attachment.Filename, err)
				SafeSend(s, m.ChannelID, fmt.Sprintf("%sI couldn't read the file '%s'. Please make sure it's a .txt file!", AteLuningningErrorPrefix, attachment.Filename))
				continue
			}

			// Add attachment content to message
			if messageContent != "" {
				messageContent += "\n\n[File: " + attachment.Filename + "]\n" + textContent
			} else {
				messageContent = "[File: " + attachment.Filename + "]\n" + textContent
			}
		}
	}

	// If there's no content at all (empty message with no processable attachments)
	if messageContent == "" {
		SafeSend(s, m.ChannelID, fmt.Sprintf("%sI see you sent something, but I couldn't find any text to process!", AteLuningningErrorPrefix))
		return
	}

	// Add user message to session
	sessionManager.AddMessage(m.Author.ID, m.ChannelID, "user", messageContent)

	// Start typing indicator in background that runs until we get a response
	typingStop := make(chan bool)
	go func() {
		ticker := time.NewTicker(5 * time.Second) // Send typing indicator every 5 seconds
		defer ticker.Stop()

		for {
			select {
			case <-typingStop:
				return
			case <-ticker.C:
				err := s.ChannelTyping(m.ChannelID)
				if err != nil {
					log.Printf("Error sending typing indicator: %v", err)
				}
			}
		}
	}()

	// Get response from DeepSeek with session context
	response, err := getDeepSeekResponseWithSession(messageContent, appConfig.DeepSeekAPIKey, DefaultDeepSeekModel, session)

	// Stop the typing indicator
	typingStop <- true
	if err != nil {
		log.Printf("DeepSeek API error in session chat: %v", err)
		errorMsg := AteLuningningErrorPrefix + "My smart brain is taking a bit too long to respond. "
		errLower := strings.ToLower(err.Error())
		if strings.Contains(errLower, "timeout") || strings.Contains(errLower, "deadline") || strings.Contains(errLower, "canceled") {
			errorMsg += "The DeepSeek servers might be busy. Please try again in a moment!"
		} else {
			errorMsg += fmt.Sprintf("Reason: %v", err)
		}
		SafeSend(s, m.ChannelID, errorMsg)
		return
	}

	// Add assistant response to session
	sessionManager.AddMessage(m.Author.ID, m.ChannelID, "assistant", response)

	// Send response (handle long messages)
	sendLongMessage(s, m.ChannelID, response, AteLuningningGreeting)
}

// processAttachment downloads and reads text from a Discord attachment
func processAttachment(attachment *discordgo.MessageAttachment) (string, error) {
	// Only process text files for now
	filename := strings.ToLower(attachment.Filename)
	if !strings.HasSuffix(filename, ".txt") {
		return "", fmt.Errorf("only .txt files are supported, got: %s", attachment.Filename)
	}

	log.Printf("Processing attachment: %s (URL: %s, Size: %d bytes)",
		attachment.Filename, attachment.URL, attachment.Size)

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Download the file from Discord's CDN
	req, err := http.NewRequest("GET", attachment.URL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}

	// Add user agent to avoid being blocked
	req.Header.Set("User-Agent", "DiscordBot (https://github.com/bwmarrin/discordgo, v0.27.1)")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to download attachment: %v", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to download attachment: HTTP %d", resp.StatusCode)
	}

	// Read the content with size limit (10MB max for safety)
	maxSize := int64(10 * 1024 * 1024) // 10MB
	limitedReader := io.LimitReader(resp.Body, maxSize)

	content, err := io.ReadAll(limitedReader)
	if err != nil {
		return "", fmt.Errorf("failed to read attachment content: %v", err)
	}

	// Convert to string and trim
	textContent := strings.TrimSpace(string(content))

	// Log success
	log.Printf("Successfully processed attachment %s: %d characters", attachment.Filename, len(textContent))

	// Check if content is too large for processing
	if len(textContent) > 10000 {
		textContent = textContent[:10000] + "\n\n[File truncated - too large for processing]"
	}

	return textContent, nil
}

// sendLongMessage handles sending messages that might exceed Discord's limits
// It splits long messages or creates .txt files for very long content
func sendLongMessage(s *discordgo.Session, channelID, content, prefix string) {
	// Discord message limit is 2000 characters
	const discordLimit = 2000
	// If content is very long (more than 3 messages worth), create a .txt file
	const txtFileThreshold = 3 * discordLimit // 6000 characters

	if len(content) <= discordLimit {
		// Short message, send normally
		if prefix != "" {
			SafeSend(s, channelID, fmt.Sprintf("%s\n%s", prefix, content))
		} else {
			// Use default prefix if none provided
			SafeSend(s, channelID, fmt.Sprintf("Ate Luningning says:\n%s", content))
		}
		return
	}

	if len(content) <= txtFileThreshold {
		// Moderately long message, split into multiple messages
		// Send initial notification message
		time.Sleep(200 * time.Millisecond)
		if prefix != "" {
			SafeSend(s, channelID, fmt.Sprintf("%s (This is a long response, splitting it up!)", prefix))
		} else {
			SafeSend(s, channelID, "Ate Luningning's response (splitting into parts)")
		}

		// Split content into chunks that fit within Discord's limit
		// Account for part numbering prefix (e.g., "[Part 1/3]\n" = ~12 chars)
		const partPrefixOverhead = 15 // Safe estimate for "[Part X/XX]\n"
		maxContentPerPart := discordLimit - partPrefixOverhead

		// Calculate total parts
		totalParts := (len(content) + maxContentPerPart - 1) / maxContentPerPart

		// Send parts
		for partNum := 1; partNum <= totalParts; partNum++ {
			// Add delay between messages (except before first part)
			if partNum > 1 {
				time.Sleep(800 * time.Millisecond)
			}

			// Calculate start and end indices
			start := (partNum - 1) * maxContentPerPart
			end := start + maxContentPerPart
			if end > len(content) {
				end = len(content)
			}

			// Create part with numbering
			partText := fmt.Sprintf("[Part %d/%d]\n%s", partNum, totalParts, content[start:end])

			// Double-check we're under limit (should be, but just in case)
			if len(partText) > discordLimit {
				// Trim if somehow over limit
				partText = partText[:discordLimit]
			}

			SafeSend(s, channelID, partText)
		}
	} else {
		// Very long message, create a .txt file
		// Create a temporary file
		tmpFile, err := os.CreateTemp("", "ateluningning_*.txt")
		if err != nil {
			log.Printf("Error creating temp file for long message: %v", err)
			// Fall back to splitting
			sendLongMessage(s, channelID, content, prefix+" (Couldn't create file, splitting instead)")
			return
		}
		defer os.Remove(tmpFile.Name()) // Clean up temp file

		// Write content to file
		_, err = tmpFile.WriteString(content)
		if err != nil {
			log.Printf("Error writing to temp file: %v", err)
			tmpFile.Close()
			// Fall back to splitting
			sendLongMessage(s, channelID, content, prefix+" (Couldn't write to file, splitting instead)")
			return
		}
		tmpFile.Close()

		// Read the file back for sending
		fileBytes, err := os.ReadFile(tmpFile.Name())
		if err != nil {
			log.Printf("Error reading temp file: %v", err)
			// Fall back to splitting
			sendLongMessage(s, channelID, content, prefix+" (Couldn't read file, splitting instead)")
			return
		}

		// Create message with file attachment
		message := fmt.Sprintf("%s (This response is very long, so I've attached it as a file!)", prefix)
		if message == " (This response is very long, so I've attached it as a file!)" {
			message = "Ate Luningning's response is very long, so I've attached it as a file!"
		}
		SafeSend(s, channelID, message)

		// Send the file
		log.Printf("Sending file attachment to channel %s: ateluningning_response.txt (%d bytes)", channelID, len(fileBytes))
		_, err = s.ChannelFileSend(channelID, "ateluningning_response.txt", bytes.NewReader(fileBytes))
		if err != nil {
			log.Printf("Error sending file: %v", err)
			// Fall back to splitting with warning
			SafeSend(s, channelID, "Oh dear! I couldn't send the file. Let me try splitting the message instead...")
			sendLongMessage(s, channelID, content, "Here's the response (split into parts):")
		} else {
			log.Printf("File sent successfully to channel %s", channelID)
		}
	}
}

// getDeepSeekResponseWithSession sends a prompt to DeepSeek API with session context
func getDeepSeekResponseWithSession(prompt, apiKey, modelName string, session *Session) (string, error) {
	if apiKey == "" {
		return "", fmt.Errorf("DeepSeek API key is not configured")
	}

	client := &http.Client{
		Timeout: RequestTimeout,
	}

	fullURL := fmt.Sprintf("https://%s%s", DeepSeekAPIHost, DeepSeekAPIPath)

	// Build messages from session history plus new prompt
	messages := make([]DeepSeekMessage, len(session.Messages))
	copy(messages, session.Messages)

	// Add the new user message
	messages = append(messages, DeepSeekMessage{
		Role:    "user",
		Content: prompt,
	})

	requestBody := DeepSeekChatRequest{
		Model:    modelName,
		Messages: messages,
		Stream:   false,
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal DeepSeek request body: %w", err)
	}

	if appConfig.Debug {
		log.Printf("DEBUG: Sending DeepSeek API request to: %s", fullURL)
		log.Printf("DEBUG: DeepSeek Request Payload: %s", string(jsonBody))
	}

	req, err := http.NewRequest("POST", fullURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", fmt.Errorf("failed to create DeepSeek API request: %w", err)
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", apiKey))

	// Try up to 3 times with exponential backoff
	var resp *http.Response
	maxRetries := 3
	for i := 0; i < maxRetries; i++ {
		resp, err = client.Do(req)
		if err == nil {
			break
		}

		// If it's a timeout error and we have retries left, wait and retry
		errLower := strings.ToLower(err.Error())
		if strings.Contains(errLower, "timeout") || strings.Contains(errLower, "deadline") || strings.Contains(errLower, "canceled") {
			if i < maxRetries-1 {
				waitTime := time.Duration(i+1) * 2 * time.Second // Exponential backoff: 2s, 4s, 6s
				log.Printf("DeepSeek API timeout (attempt %d/%d), retrying in %v...", i+1, maxRetries, waitTime)
				time.Sleep(waitTime)
				continue
			}
		}
		// For other errors, break immediately
		break
	}

	if err != nil {
		return "", fmt.Errorf("DeepSeek API request failed after %d attempts: %w", maxRetries, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 50*1024))
	if err != nil {
		return "", fmt.Errorf("error reading DeepSeek API response: %w", err)
	}

	if appConfig.Debug {
		log.Printf("DEBUG: DeepSeek Response Status: %d", resp.StatusCode)
		log.Printf("DEBUG: DeepSeek Response Body: %s", string(body))
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("DeepSeek API returned status: %d, body: %s", resp.StatusCode, string(body))
	}

	var deepSeekResponse DeepSeekChatResponse
	if err := json.Unmarshal(body, &deepSeekResponse); err != nil {
		return "", fmt.Errorf("failed to parse DeepSeek API response: %w", err)
	}

	if len(deepSeekResponse.Choices) == 0 {
		return "", fmt.Errorf("DeepSeek API returned no choices")
	}

	return deepSeekResponse.Choices[0].Message.Content, nil
}

// --- Database Functions for Command Locking ---

// initDB initializes the SQLite database connection and creates the command_locks table.
// IMPORTANT: This version assumes bot.db is deleted or empty for command_locks for clean setup.
func initDB() error {
	var err error
	db, err = sql.Open("sqlite3", DatabaseFile)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Create command_locks table with composite primary key (command_name, channel_id)
	createTableSQL := `
    CREATE TABLE IF NOT EXISTS command_locks (
        command_name TEXT NOT NULL,
        channel_id TEXT NOT NULL,
        is_locked INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (command_name, channel_id)
    );`
	_, err = db.Exec(createTableSQL)
	if err != nil {
		return fmt.Errorf("failed to create command_locks table: %w", err)
	}
	log.Println("Database initialized and command_locks table checked.")
	return nil
}

// setCommandLocked updates the locked status of a command for a specific channel.
func setCommandLocked(command, channelID string, locked bool) error {
	lockValue := 0
	if locked {
		lockValue = 1
	}
	stmt, err := db.Prepare("INSERT OR REPLACE INTO command_locks (command_name, channel_id, is_locked) VALUES (?, ?, ?)")
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	_, err = stmt.Exec(command, channelID, lockValue)
	if err != nil {
		return fmt.Errorf("failed to set command lock status for channel %s: %w", channelID, err)
	}
	return nil
}

// isCommandLocked checks if a command is currently locked for a specific channel.
func isCommandLocked(command, channelID string) (bool, error) {
	var locked int
	row := db.QueryRow("SELECT is_locked FROM command_locks WHERE command_name = ? AND channel_id = ?", command, channelID)
	err := row.Scan(&locked)
	if err == sql.ErrNoRows {
		return false, nil // Command not in DB for this channel, so it's not locked by default
	}
	if err != nil {
		return false, fmt.Errorf("failed to query command lock status: %w", err)
	}
	return locked == 1, nil
}

// isAdmin checks if a user is one of the designated administrators.
func isAdmin(userID string) bool {
	for _, adminID := range appConfig.AdminUserIDs {
		if userID == adminID {
			return true
		}
	}
	return false
}


// messageCreate handles incoming Discord messages dynamically using message context
func messageCreate(s *discordgo.Session, m *discordgo.MessageCreate) {
	if m.Author.ID == s.State.User.ID {
		return
	}

	// Log incoming message and attachments
	logContent := m.Content
	hasAttachments := len(m.Attachments) > 0

	// Build log message
	logMsg := fmt.Sprintf("Message received in channel %s from %s (ID: %s)", m.ChannelID, m.Author.Username, m.Author.ID)

	if logContent != "" {
		if len(logContent) > 100 {
			logContent = logContent[:100] + "..."
		}
		logMsg += fmt.Sprintf(": %s", logContent)
	}

	if hasAttachments {
		attachmentNames := []string{}
		for _, att := range m.Attachments {
			attachmentNames = append(attachmentNames, att.Filename)
		}
		logMsg += fmt.Sprintf(" [Attachments: %s]", strings.Join(attachmentNames, ", "))
	}

	log.Printf(logMsg)

	// Check if user has an active session (for session-based chat without ! prefix)
	// Also check for attachments even without text
	hasActiveSession := false
	var activeSession *Session
	if session, exists := sessionManager.GetSession(m.Author.ID, m.ChannelID); exists {
		hasActiveSession = true
		activeSession = session
	}

	// Handle session chat (with or without text, but with possible attachments)
	if hasActiveSession && (!strings.HasPrefix(m.Content, Prefix) || len(m.Attachments) > 0) {
		handleSessionChat(s, m, activeSession)
		return
	}

	// If no active session and no command prefix, ignore
	if !strings.HasPrefix(m.Content, Prefix) {
		return
	}

	content := strings.TrimPrefix(m.Content, Prefix)
	parts := strings.Fields(content)
	if len(parts) == 0 {
		return
	}

	command := parts[0]
	args := parts[1:]

	// Declare err at the beginning of the function's scope
	var err error

	// --- Admin Commands (Requires isAdmin check first) ---
	if command == "lock" || command == "unlock" {
		if !isAdmin(m.Author.ID) {
			SafeSend(s, m.ChannelID, fmt.Sprintf("%sOh, I'm sorry, my dear, only Ate Luningning's special helpers can use that command!", AteLuningningErrorPrefix))
			return
		}

		if len(args) < 1 {
			SafeSend(s, m.ChannelID, fmt.Sprintf("%sPlease tell Ate Luningning which command to %s, like `!%s %s`.", AteLuningningGreeting, command, command, AteLuningningAICommand))
			return
		}
		targetCommand := strings.ToLower(args[0])

		if targetCommand != AteLuningningAICommand && targetCommand != "horoscope" && targetCommand != WorkStartCommand && targetCommand != "yokona" {
			SafeSend(s, m.ChannelID, fmt.Sprintf("%sI can only %s the `!%s`, `!horoscope`, `!%s`, or `!yokona` commands for now, dear.", AteLuningningErrorPrefix, command, AteLuningningAICommand, WorkStartCommand))
			return
		}

		isLock := (command == "lock")
		err = setCommandLocked(targetCommand, m.ChannelID, isLock) // Use = for assignment
		if err != nil {
			log.Printf("Error setting lock status for %s in channel %s: %v", targetCommand, m.ChannelID, err)
			SafeSend(s, m.ChannelID, AteLuningningErrorPrefix + fmt.Sprintf("I couldn't change the status of `!%s` in this channel right now, my dear. Please check my recipe book (logs)!", targetCommand))
			return
		}

		status := "locked"
		if !isLock {
			status = "unlocked"
		}
		SafeSend(s, m.ChannelID, fmt.Sprintf("%sOkay, my dear, the `!%s` command is now **%s** in this channel!", AteLuningningGreeting, targetCommand, status))
		return // Handled admin command, so return
	}
	// --- End Admin Commands ---

	// --- Check for locked commands before proceeding ---
	// Apply lock check for !horoscope, !askluningning, !chismis, and !yokona
	if command == "horoscope" || command == AteLuningningAICommand || command == WorkStartCommand || command == "yokona" {
		isLocked, checkErr := isCommandLocked(command, m.ChannelID) // Use a new variable for `err` here to avoid shadowing outside `if`
		if checkErr != nil {
			log.Printf("Database error checking %s lock status: %v", command, checkErr)
			SafeSend(s, m.ChannelID, AteLuningningErrorPrefix + "My little database helper is having a problem. Please try again later!")
			return
		}
		if isLocked {
			SafeSend(s, m.ChannelID, fmt.Sprintf("%sI'm sorry, my dear, the `!%s` command is currently **locked** in this channel. Ate Luningning needs a break for that one right now!", AteLuningningErrorPrefix, command))
			return
		}
	}
	// --- End lock check ---

	switch command {
	case "hello":
		SafeSend(s, m.ChannelID, fmt.Sprintf("%sHello there, my dear!!!!! %s is here to serve you some wisdom and good vibes. What can I get for you today? Try `!help` for the menu!", AteLuningningGreeting, AteLuningningName))

	case "ping":
		latency := time.Since(m.Timestamp)
		SafeSend(s, m.ChannelID, fmt.Sprintf("Oh, a little tap on my lunch counter! Pong! 🏓 (My little helper says I'm super fast, only %s!)", latency.Round(time.Millisecond)))

	case "verse":
		verse, verseErr := getBibleVerse() // Use new variable to avoid shadowing global err
		if verseErr != nil {
			log.Printf("Verse retrieval error: %v", verseErr)
			SafeSend(s, m.ChannelID, AteLuningningErrorPrefix + "My apologies, dear, I couldn't quite whip that up right now. Try again later, okay?")
			return
		}
		SafeSend(s, m.ChannelID, fmt.Sprintf("%sHere's some spiritual nourishment for your soul, straight from Ate Luningning's pantry of wisdom! 📖", AteLuningningGreeting))
		embed := createVerseEmbed(verse)
		SafeSendEmbed(s, m.ChannelID, embed)

	case "horoscope": // This command now uses DeepSeek
		if appConfig.DeepSeekAPIKey == "" {
			SafeSend(s, m.ChannelID, AteLuningningErrorPrefix + "It looks like my horoscope crystal ball isn't connected right now. Please tell my programmer to check the `DEEPSEEK_API_KEY`!")
			return
		}
		if len(args) < 1 {
			SafeSend(s, m.ChannelID, fmt.Sprintf("%sPlease tell Ate Luningning your zodiac sign, my dear, like `!horoscope leo`.", AteLuningningGreeting))
			return
		}
		sign := args[0]

		SafeSend(s, m.ChannelID, fmt.Sprintf("%sLet me consult the stars for you, my dear %s...", AteLuningningGreeting, CapitalizeFirstLetter(strings.ToLower(sign))))

		// Start typing indicator in background that runs until we get a response
		typingStop := make(chan bool)
		go func() {
			ticker := time.NewTicker(5 * time.Second) // Send typing indicator every 5 seconds
			defer ticker.Stop()

			for {
				select {
				case <-typingStop:
					return
				case <-ticker.C:
					err := s.ChannelTyping(m.ChannelID)
					if err != nil {
						log.Printf("Error sending typing indicator: %v", err)
					}
				}
			}
		}()

		// Call the new DeepSeek-based horoscope function
		horoscopeData, horoscopeErr := getDeepSeekHoroscope(sign, appConfig.DeepSeekAPIKey, DefaultDeepSeekModel) // Use new variable for err

		// Stop the typing indicator
		typingStop <- true
		if horoscopeErr != nil {
			log.Printf("Horoscope retrieval error for %s from DeepSeek: %v", sign, horoscopeErr)
			errorMsg := AteLuningningErrorPrefix + "I couldn't quite read the stars for you right now. "
			errLower := strings.ToLower(horoscopeErr.Error())
			if strings.Contains(errLower, "timeout") || strings.Contains(errLower, "deadline") || strings.Contains(errLower, "canceled") {
				errorMsg += "The DeepSeek servers might be busy. Please try again in a moment!"
			} else {
				errorMsg += fmt.Sprintf("Reason: %v. Please try again or provide a valid sign.", horoscopeErr)
			}
			SafeSend(s, m.ChannelID, errorMsg)
			return
		}

		SafeSend(s, m.ChannelID, fmt.Sprintf("%sLet's see what the stars are cooking for you today, my dear!", AteLuningningGreeting))
		embed := createHoroscopeEmbed(horoscopeData)
		SafeSendEmbed(s, m.ChannelID, embed)
		SafeSend(s, m.ChannelID, "*(Just a little heads-up from Ate Luningning: This horoscope is your daily forecast, cooked by my smart brain!)*")
	
	case AteLuningningAICommand: // Command for general AI questions (one-time)
		if appConfig.DeepSeekAPIKey == "" {
			SafeSend(s, m.ChannelID, AteLuningningErrorPrefix + "My smart brain isn't fully connected right now. Please tell my programmer to set the `DEEPSEEK_API_KEY`!")
			return
		}

		// Process message content and attachments
		prompt := strings.Join(args, " ")
		hasAttachments := len(m.Attachments) > 0

		// If there are attachments, process them
		if hasAttachments {
			for _, attachment := range m.Attachments {
				textContent, err := processAttachment(attachment)
				if err != nil {
					log.Printf("Error processing attachment %s: %v", attachment.Filename, err)
					SafeSend(s, m.ChannelID, fmt.Sprintf("%sI couldn't read the file '%s'. Please make sure it's a .txt file!", AteLuningningErrorPrefix, attachment.Filename))
					continue
				}

				// Add attachment content to prompt
				if prompt != "" {
					prompt += "\n\n[File: " + attachment.Filename + "]\n" + textContent
				} else {
					prompt = "[File: " + attachment.Filename + "]\n" + textContent
				}
			}
		}

		// Check if we have any content to process
		if prompt == "" && !hasAttachments {
			SafeSend(s, m.ChannelID, fmt.Sprintf("%sWhat do you want to ask my smart brain, dear? Just type `!%s <your question here>` or attach a .txt file!", AteLuningningGreeting, AteLuningningAICommand))
			return
		}

		if prompt == "" && hasAttachments {
			prompt = "Please analyze the content of the attached file(s)."
		}

		SafeSend(s, m.ChannelID, fmt.Sprintf("%sAte Luningning is consulting the magic crystal ball for you! Give me a moment while I prepare your answer...", AteLuningningGreeting))

		// Start typing indicator in background that runs until we get a response
		typingStop := make(chan bool)
		go func() {
			ticker := time.NewTicker(5 * time.Second) // Send typing indicator every 5 seconds
			defer ticker.Stop()

			for {
				select {
				case <-typingStop:
					return
				case <-ticker.C:
					err = s.ChannelTyping(m.ChannelID)
					if err != nil {
						log.Printf("Error sending typing indicator: %v", err)
					}
				}
			}
		}()

		deepSeekResponse, deepSeekErr := getDeepSeekResponse(prompt, appConfig.DeepSeekAPIKey, DefaultDeepSeekModel) // Use new variable for err

		// Stop the typing indicator
		typingStop <- true
		if deepSeekErr != nil {
			log.Printf("DeepSeek API error: %v", deepSeekErr)
			errorMsg := AteLuningningErrorPrefix + "My smart brain is taking a bit too long to respond. "
			errLower := strings.ToLower(deepSeekErr.Error())
			if strings.Contains(errLower, "timeout") || strings.Contains(errLower, "deadline") || strings.Contains(errLower, "canceled") {
				errorMsg += "The DeepSeek servers might be busy. Please try again in a moment!"
			} else {
				errorMsg += fmt.Sprintf("Reason: %v", deepSeekErr)
			}
			SafeSend(s, m.ChannelID, errorMsg)
			return
		}

		// Handle long messages - split or create .txt file
		sendLongMessage(s, m.ChannelID, deepSeekResponse, "Here's what the cosmos revealed for you, my dear:")

	case WorkStartCommand: // Command for session-based chat
		if appConfig.DeepSeekAPIKey == "" {
			SafeSend(s, m.ChannelID, AteLuningningErrorPrefix + "My smart brain isn't fully connected right now. Please tell my programmer to set the `DEEPSEEK_API_KEY`!")
			return
		}

		// Check if user already has an active session
		if session, exists := sessionManager.GetSession(m.Author.ID, m.ChannelID); exists {
			timeSinceLastActive := time.Since(session.LastActive)
			SafeSend(s, m.ChannelID, fmt.Sprintf("%sYou already have an active work session, my dear! (Last active: %s ago)", AteLuningningGreeting, formatDuration(timeSinceLastActive)))
			return
		}

		// Start new session
		_ = sessionManager.StartSession(m.Author.ID, m.ChannelID)
		SafeSend(s, m.ChannelID, fmt.Sprintf("%sWork session started! I'll remember our conversation for the next 30 minutes. Just talk to me normally (no need for !commands). Type `!yokona` to end the session early.", AteLuningningGreeting))

		// Add initial system message
		sessionManager.AddMessage(m.Author.ID, m.ChannelID, "system", "You are Ate Luningning, a friendly and helpful Filipino auntie who gives advice with warmth and humor. You're having a conversation with someone who started a work session with you.")

	case "yokona": // Command to end session
		if sessionManager.EndSession(m.Author.ID, m.ChannelID) {
			SafeSend(s, m.ChannelID, fmt.Sprintf("%sWork session ended! Our conversation has been cleared. Start a new one with `!chismis` whenever you're ready, my dear!", AteLuningningGreeting))
		} else {
			SafeSend(s, m.ChannelID, fmt.Sprintf("%sYou don't have an active work session to end, dear. Start one with `!chismis`!", AteLuningningGreeting))
		}

	case "help":
		helpEmbed := &discordgo.MessageEmbed{
			Title:       "🤖 Ate Luningning's Menu of Services",
			Description: "Here are the delicious commands I can serve you today:",
			Color:       0x7289DA,
			Fields: []*discordgo.MessageEmbedField{
				{
					Name:   "`!hello`",
					Value:  "A warm greeting from Ate Luningning!",
					Inline: true,
				},
				{
					Name:   "`!ping`",
					Value:  "A quick tap to check if Ate Luningning's kitchen is open!",
					Inline: true,
				},
				{
					Name:   "`!uptime`",
					Value:  "See how long Ate Luningning's been serving you up!",
					Inline: true,
				},
				{
					Name:   "`!verse`",
					Value:  "Some spiritual nourishment from the Good Book! 📖",
					Inline: true,
				},
				{
					Name:   "`!horoscope <zodiacSign>`",
					Value:  "What the stars are cooking for your daily forecast, powered by my smart brain! (e.g., `!horoscope leo`).",
					Inline: true,
				},
				{
					Name:   fmt.Sprintf("`!%s <prompt>`", AteLuningningAICommand),
					Value:  "Ask Ate Luningning's smart brain anything! (e.g., `!askluningning What is the capital of France?`).",
					Inline: false,
				},
				{
					Name:   "`!chismis`",
					Value:  "Start a session-based chat with Ate Luningning! I'll remember our conversation for 30 minutes. Just talk to me normally after starting.",
					Inline: false,
				},
				{
					Name:   "`!yokona`",
					Value:  "End your current work session and clear the conversation history.",
					Inline: false,
				},
				{
					Name:   "`!calc <num1> <op> <num2>`",
					Value:  "Let Ate Luningning crunch those numbers for you! (e.g., `!calc 5 + 3`). Supports `+`, `-`, `*`, `/`.",
					Inline: false,
				},
				{
					Name:   "`!choose <option1>, <option2>, ...`",
					Value:  "Can't decide? Let Ate Luningning pick from the menu for you! (e.g., `!choose sinigang, adobo, pancit`).",
					Inline: false,
				},
				{
					Name:   "`!roll <NdX>`",
					Value:  "Time to shake things up! Ate Luningning will roll some dice for you (e.g., `!roll 1d6`, `!roll 2d10`).",
					Inline: false,
				},
				{
					Name:   "⚙️ Admin Commands (For Ate Luningning's helpers)",
					Value:  fmt.Sprintf("`!lock <command>` / `!unlock <command>` : To temporarily turn off/on services like `!%s` or `!horoscope` **in this channel only**. (Only for special helpers!)", AteLuningningAICommand),
					Inline: false,
				},
			},
			Timestamp: time.Now().Format(time.RFC3339),
			Footer: &discordgo.MessageEmbedFooter{
				Text: "Ate Luningning is always here to help you get your daily dose of wisdom and fun!",
			},
		}
		SafeSendEmbed(s, m.ChannelID, helpEmbed)

	case "uptime":
		duration := time.Since(startTime)
		SafeSend(s, m.ChannelID, fmt.Sprintf("%sMy kitchen's been open for business for: %s! Always ready to serve!", AteLuningningGreeting, formatDuration(duration)))

	case "calc":
		if len(args) != 3 {
			SafeSend(s, m.ChannelID, fmt.Sprintf("%sUsage: `!calc <number1> <operator> <number2>` (e.g., `!calc 5 + 3`)", AteLuningningGreeting))
			return
		}

		num1, num1Err := strconv.ParseFloat(args[0], 64) // Use new variable for err
		num2, num2Err := strconv.ParseFloat(args[2], 64) // Use new variable for err
		operator := args[1]

		if num1Err != nil || num2Err != nil {
			SafeSend(s, m.ChannelID, AteLuningningErrorPrefix + "Hmm, those don't look like proper numbers, my dear.")
			return
		}

		var result float64
		var opSuccess bool = true

		switch operator {
		case "+":
			result = num1 + num2
		case "-":
			result = num1 - num2
		case "*":
			result = num1 * num2
		case "/":
			if num2 == 0 {
				SafeSend(s, m.ChannelID, AteLuningningErrorPrefix + "Oh, we can't divide by zero! That's a big no-no in my kitchen!")
				return
			}
			result = num1 / num2
		default:
			SafeSend(s, m.ChannelID, AteLuningningErrorPrefix + "That's not an operator I know, dear. Please use `+`, `-`, `*`, or `/`.")
			opSuccess = false
		}

		if opSuccess {
			SafeSend(s, m.ChannelID, fmt.Sprintf("Ate Luningning's calculation says: %.2f", result))
		}

	case "choose":
		if len(args) == 0 {
			SafeSend(s, m.ChannelID, fmt.Sprintf("%sUsage: `!choose <option1>, <option2>, ...`", AteLuningningGreeting))
			return
		}
		
		optionsStr := strings.Join(args, " ")
		options := strings.Split(optionsStr, ",")
		
		cleanOptions := []string{}
		for _, opt := range options {
			trimmed := strings.TrimSpace(opt)
			if trimmed != "" {
				cleanOptions = append(cleanOptions, trimmed)
			}
		}

		if len(cleanOptions) == 0 {
			SafeSend(s, m.ChannelID, AteLuningningErrorPrefix + "Please give me at least one valid option to choose from, dear.")
			return
		}

		chosen := cleanOptions[rand.Intn(len(cleanOptions))]
		SafeSend(s, m.ChannelID, fmt.Sprintf("%sHmm, tough choice, huh? Let Ate Luningning help you pick from the menu! I say: **%s**", AteLuningningGreeting, chosen))

	case "roll":
		if len(args) != 1 {
			SafeSend(s, m.ChannelID, fmt.Sprintf("%sUsage: `!roll <NdX>` (e.g., `!roll 1d6`, `!roll 2d10`)", AteLuningningGreeting))
			return
		}

		rollStr := strings.ToLower(args[0])
		parts := strings.Split(rollStr, "d")
		if len(parts) != 2 {
			SafeSend(s, m.ChannelID, AteLuningningErrorPrefix + "That's not how we roll dice, dear. Please use `NdX` (e.g., `1d6`).")
			return
		}

		numDice, numDiceErr := strconv.Atoi(parts[0]) // Use new variable for err
		sides, sidesErr := strconv.Atoi(parts[1])     // Use new variable for err

		if numDiceErr != nil || sidesErr != nil || numDice <= 0 || sides <= 0 {
			SafeSend(s, m.ChannelID, AteLuningningErrorPrefix + "Invalid dice format. N and X must be positive numbers (e.g., `1d6`).")
			return
		}
		if numDice > 100 || sides > 1000 {
			SafeSend(s, m.ChannelID, AteLuningningErrorPrefix + "Oh my, that's too many dice or too many sides! (Max 100d1000 in my kitchen!)")
			return
		}

		total := 0
		rolls := []int{}
		for i := 0; i < numDice; i++ {
			roll := rand.Intn(sides) + 1
			total += roll
			rolls = append(rolls, roll)
		}

		if numDice == 1 {
			SafeSend(s, m.ChannelID, fmt.Sprintf("Time to shake things up a bit! Ate Luningning is rolling the dice for you... Rolled %s: **%d**", rollStr, total))
		} else {
			SafeSend(s, m.ChannelID, fmt.Sprintf("Time to shake things up a bit! Ate Luningning is rolling the dice for you... Rolled %s: %v = **%d**", rollStr, rolls, total))
		}

	default:
		SafeSend(s, m.ChannelID, fmt.Sprintf("Oh, dear, I didn't quite catch that. Ate Luningning doesn't know that command. Try `!help` to see all my services!"))
	}
}

func main() {
	var err error
	var dg *discordgo.Session // Corrected: Declare dg here

	appConfig, err = loadConfiguration()
	if err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

	configureLogging(appConfig.Debug)

	// Initialize session manager
	sessionManager = NewSessionManager()

	// Start session cleanup goroutine
	go func() {
		ticker := time.NewTicker(5 * time.Minute) // Check every 5 minutes
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				sessionManager.CleanupInactiveSessions()
			}
		}
	}()

	// Initialize database (for command locking)
	err = initDB() // Make sure bot.db is deleted before running this version!
	if err != nil {
		log.Fatalf("Database initialization error: %v", err)
	}
	defer func() {
		if db != nil {
			closeErr := db.Close() // Use a new variable for `err` here to avoid shadowing
			if closeErr != nil {
				log.Printf("Error closing database: %v", closeErr)
			}
		}
	}()

	dg, err = discordgo.New("Bot " + appConfig.DiscordToken) // Use = for assignment
	if err != nil {
		log.Fatalf("Failed to create Discord session: %v", err)
	}

	dg.AddHandler(readyHandler)
	dg.AddHandler(messageCreate)

	dg.Identify.Intents = discordgo.IntentsGuildMessages | discordgo.IntentsMessageContent
	
	err = dg.Open() // Use = for assignment
	if err != nil {
		log.Fatalf("Cannot open Discord connection: %v", err)
	}
	defer func() {
		closeErr := dg.Close() // Use a new variable for `err` here to avoid shadowing
		if closeErr != nil {
			log.Printf("Error closing Discord connection: %v", closeErr)
		}
	}()

	log.Println("Bot is now running. Press CTRL-C to exit.")

	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-sc

	log.Println("Received termination signal. Shutting down...")
}
