package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Configuration Constants
const (
	MongoURI          = "mongodb://localhost:27017"
	LLMAPIEndpoint    = "http://localhost:11434/v1/chat/completions"
	LLMAPIKey         = "ollama"
	LLMModel          = "qwen2.5:3b"
	DiscordWebhook    = "https://discord.com/api/webhooks/1517207643725238282/LWBVF9Uqs7IR_bjpFgxNoaLvLx9OvHK6eI7eA3gVHOKvqDZBM8giiLc4iOEhxcPm3M8l"
	PollingInterval   = 3 * time.Second
)

// --- MongoDB / Business Object Schemas ---

type SessionEvent struct {
	Timestamp   string   `bson:"timestamp" json:"timestamp"`
	RuleID      string   `bson:"rule_id" json:"rule_id"`
	Description string   `bson:"description" json:"description"`
	Decoder     string   `bson:"decoder" json:"decoder"`
	Level       int      `bson:"level" json:"level"`
	Mitre       []string `bson:"mitre" json:"mitre"`
}

type IncidentSession struct {
	ID            primitive.ObjectID `bson:"_id"`
	SessionID     string             `bson:"session_id"`
	SrcIP         string             `bson:"src_ip"`
	Status        string             `bson:"status"`
	Severity      string             `bson:"severity"`
	SeverityScore int                `bson:"severity_score"`
	StartTime     time.Time          `bson:"start_time"`
	LastSeen      time.Time          `bson:"last_seen"`
	InitialAccess bool               `bson:"initial_access"`
	Discovery     bool               `bson:"discovery"`
	Execution     bool               `bson:"execution"`
	Persistence   bool               `bson:"persistence"`
	EventCount    int                `bson:"event_count"`
	Events        []SessionEvent     `bson:"events"`
	AIAnalyzed    bool               `bson:"ai_analyzed"`
}

type InvestigationReport struct {
	ID                 primitive.ObjectID `bson:"_id,omitempty" json:"-"`
	SessionID          string             `bson:"session_id" json:"session_id"`
	SrcIP              string             `bson:"src_ip" json:"src_ip"`
	Severity           string             `bson:"severity" json:"severity"`
	Confidence         int                `bson:"confidence" json:"confidence"`
	AttackPhases       []string           `bson:"attack_phases" json:"attack_phases"`
	MitreTechniques    []string           `bson:"mitre_techniques" json:"mitre_techniques"`
	Summary            string             `bson:"summary" json:"summary"`
	Evidence           []string           `bson:"evidence" json:"evidence"`
	RecommendedActions []string           `bson:"recommended_actions" json:"recommended_actions"`
	CreatedAt          time.Time          `bson:"created_at" json:"created_at"`
}

// --- LLM Interaction Schemas ---

type OpenAIRequest struct {
	Model          string         `json:"model"`
	Messages       []OpenAIMessage `json:"messages"`
	ResponseFormat struct {
		Type string `json:"type"`
	} `json:"response_format"`
	Temperature float64 `json:"temperature"`
}

type OpenAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type OpenAIResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

// --- Discord Webhook Schemas ---

type DiscordEmbed struct {
	Title     string         `json:"title"`
	Color     int            `json:"color"`
	Timestamp string         `json:"timestamp,omitempty"`
	Fields    []DiscordField `json:"fields"`
	Footer    *DiscordFooter `json:"footer,omitempty"`
}

type DiscordField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline,omitempty"`
}

type DiscordFooter struct {
	Text string `json:"text"`
}

type DiscordPayload struct {
	Embeds []DiscordEmbed `json:"embeds"`
}

func main() {
	ctx := context.Background()

	// 1. Initialize MongoDB Connection
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(MongoURI))
	if err != nil {
		log.Fatal("Failed to connect to MongoDB:", err)
	}
	defer func() {
		if dErr := client.Disconnect(ctx); dErr != nil {
			log.Printf("Error closing MongoDB Connection: %v", dErr)
		}
	}()

	db := client.Database("wazuh")
	sessionsColl := db.Collection("sessions")
	investigationsColl := db.Collection("investigations")

	fmt.Println("Wazuh AI Analyzer Service started safely as a continuous daemon...")

	// 2. Core Worker Loop
	for {
		processedCount := 0

		// Target Filter: Fetch high/critical severity items waiting for analytical execution
		filter := bson.M{
			"severity":    bson.M{"$in": []string{"high", "critical"}},
			"ai_analyzed": bson.M{"$ne": true},
		}

		cursor, err := sessionsColl.Find(ctx, filter)
		if err != nil {
			log.Printf("Error fetching eligible execution sessions: %v\n", err)
			time.Sleep(PollingInterval)
			continue
		}

		for cursor.Next(ctx) {
			var session IncidentSession
			if err := cursor.Decode(&session); err != nil {
				log.Printf("BSON Unmarshalling structural failure: %v\n", err)
				continue
			}

			processedCount++

			// 3. Process Context & Invoke AI Agent Integration
			report, err := analyzeSessionWithLLM(session)
			if err != nil {
				log.Printf("[ERROR] Skipping current pipeline run for session %s due to API failure: %v\n", session.SessionID, err)
				continue // Keep uncorrelated state flag untouched so system retries next loop cycle
			}

			// 4. Save Investigation Report Data
			report.CreatedAt = time.Now()
			insertResult, err := investigationsColl.InsertOne(ctx, report)
			if err != nil {
				log.Printf("Failed to record document data into collections: %v\n", err)
				continue
			}
			investigationID := insertResult.InsertedID.(primitive.ObjectID)

			// 5. Update Original Session Status Cleanly
			_, err = sessionsColl.UpdateOne(
				ctx,
				bson.M{"_id": session.ID},
				bson.M{
					"$set": bson.M{
						"ai_analyzed":      true,
						"investigation_id": investigationID,
					},
				},
			)
			if err != nil {
				log.Printf("Failed to update parent audit session lifecycle properties: %v\n", err)
				continue
			}

			// 6. Handle Out-of-Band Incident Notifications (WhatsApp Router Hooks)
			if report.Confidence >= 80 {
				dispatchNotification(report)
			}
		}
		cursor.Close(ctx)

		// Diagnostic Logging Summary per polling interval window
		remainingCount, _ := sessionsColl.CountDocuments(ctx, filter)
		fmt.Printf("processed=%d analytical_backlog=%d\n", processedCount, remainingCount)

		time.Sleep(PollingInterval)
	}
}

// analyzeSessionWithLLM handles context compilation, prompt creation, and rigid parsing validation.
func analyzeSessionWithLLM(session IncidentSession) (*InvestigationReport, error) {
	// Cap events sent to LLM to keep prompt within CPU-feasible token budget.
	// When exceeding the cap, keep the first events (initial access) and last events (impact/persistence),
	// which are the most important for attack-chain reconstruction.
	const maxEvents = 25
	events := session.Events
	if len(events) > maxEvents {
		half := maxEvents / 2
		events = append(events[:half], events[len(events)-half:]...)
	}

	// Synthesize precise historical timeline data from session slices
	var timelineContext bytes.Buffer
	var evidenceList []string
	for idx, event := range events {
		timelineContext.WriteString(fmt.Sprintf("%d. %s (Rule: %s, Decoder: %s)\n", idx+1, event.Description, event.RuleID, event.Decoder))
		evidenceList = append(evidenceList, event.Description)
	}
	if len(session.Events) > maxEvents {
		timelineContext.WriteString(fmt.Sprintf("\n(Note: %d total events, showing %d key events for brevity)\n", len(session.Events), len(events)))
	}

	systemPrompt := `You are an expert Security Operations Center (SOC) incident responder.
Your responsibility is to analyze historical correlation alerts and transform them into clear, actionable structural JSON investigation summaries.
You must return a raw JSON object matching EXACTLY the requested structure fields. Do not write text outside the JSON block.`

	userPrompt := fmt.Sprintf(`Analyze this malicious activity session:
Metadata Context:
- Source IP: %s
- Current Session Severity Tier: %s
- Aggregated Attack Risk Weight Score: %d
- Total Sequential Events Tracked: %d
- Matrix Milestones -> Initial Access: %t | Discovery: %t | Execution: %t | Persistence: %t

Observed Activity Timeline:
%s

Your JSON response must contain exactly these structural fields:
{
  "summary": "A concise overview explaining what took place, container scope implications, and suspected intent.",
  "confidence": (Integer score value between 1 and 100 evaluating evidence logic validity),
  "attack_phases": ["Explicit structural list selecting matching domains from: Initial Access, Discovery, Execution, File Transfer, Persistence, Impact"],
  "recommended_actions": ["Clear bullet points of immediate tactical incident containment instructions"]
}`, session.SrcIP, session.Severity, session.SeverityScore, session.EventCount, session.InitialAccess, session.Discovery, session.Execution, session.Persistence, timelineContext.String())

	// Build Structured OpenAI API Request Schema Configuration
	reqBody := OpenAIRequest{
		Model:       LLMModel,
		Temperature: 0.1, // Low variation threshold config for consistency metrics
	}
	reqBody.ResponseFormat.Type = "json_object"
	reqBody.Messages = []OpenAIMessage{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: userPrompt},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", LLMAPIEndpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+LLMAPIKey)

	client := &http.Client{Timeout: 600 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request returned non-OK status code: %d, response: %s", resp.StatusCode, string(respBytes))
	}

	var openAIResp OpenAIResponse
	if err := json.Unmarshal(respBytes, &openAIResp); err != nil {
		return nil, err
	}

	if len(openAIResp.Choices) == 0 {
		return nil, fmt.Errorf("received zero structural choices back from the LLM model array")
	}

	// Structural Payload Parsing Target Map
	var rawReport struct {
		Summary            string   `json:"summary"`
		Confidence         int      `json:"confidence"`
		AttackPhases       []string `json:"attack_phases"`
		RecommendedActions []string `json:"recommended_actions"`
	}

	err = json.Unmarshal([]byte(openAIResp.Choices[0].Message.Content), &rawReport)
	if err != nil {
		return nil, fmt.Errorf("failed parsing structured string back into schema validation targets: %v", err)
	}

	// Aggregate unique MITRE ATT&CK techniques from session events (authoritative Wazuh rule data)
	mitreSet := map[string]bool{}
	var mitreTechniques []string
	for _, ev := range events {
		for _, m := range ev.Mitre {
			if !mitreSet[m] {
				mitreSet[m] = true
				mitreTechniques = append(mitreTechniques, m)
			}
		}
	}

	// Synthesize nested variables together into unified investigation model structure map
	report := &InvestigationReport{
		SessionID:          session.SessionID,
		SrcIP:              session.SrcIP,
		Severity:           session.Severity,
		Confidence:         rawReport.Confidence,
		AttackPhases:       rawReport.AttackPhases,
		MitreTechniques:    mitreTechniques,
		Summary:            rawReport.Summary,
		Evidence:           evidenceList,
		RecommendedActions: rawReport.RecommendedActions,
	}

	return report, nil
}
// dispatchNotification isolates structural details and targets external Webhook infrastructure.
func dispatchNotification(report *InvestigationReport) {
	// Synthesize clean path data out of arrays
	var attackPathStr string
	for idx, phase := range report.AttackPhases {
		if idx == 0 {
			attackPathStr += phase
		} else {
			attackPathStr += " → " + phase
		}
	}

	var evidenceStr string
	for _, evidence := range report.Evidence {
		evidenceStr += fmt.Sprintf("- %s\n", evidence)
	}

	var recommendationsStr string
	for _, rec := range report.RecommendedActions {
		recommendationsStr += fmt.Sprintf("- %s\n", rec)
	}

	// Map severity tier to Discord embed color (decimal RGB int)
	severityColor := map[string]int{
		"critical": 16711680, // red
		"high":     16744448, // orange
		"medium":   16776960, // yellow
		"low":      39423,    // blue
	}
	color, ok := severityColor[report.Severity]
	if !ok {
		color = 9807153 // default gray-purple
	}

	// Discord caps field values at 1024 chars; guard against oversized evidence/recommendation payloads
	if len(evidenceStr) > 1024 {
		evidenceStr = evidenceStr[:1021] + "..."
	}
	if len(recommendationsStr) > 1024 {
		recommendationsStr = recommendationsStr[:1021] + "..."
	}

	// Build MITRE ATT&CK technique summary string
	var mitreStr string
	for _, m := range report.MitreTechniques {
		mitreStr += fmt.Sprintf("- %s\n", m)
	}
	if mitreStr == "" {
		mitreStr = "N/A"
	}
	if len(mitreStr) > 1024 {
		mitreStr = mitreStr[:1021] + "..."
	}

	// Compile target production embed structure mapping definitions
	payload := DiscordPayload{
		Embeds: []DiscordEmbed{
			{
				Title:     fmt.Sprintf("🚨 %s SEVERITY INCIDENT", strings.ToUpper(report.Severity)),
				Color:     color,
				Timestamp: report.CreatedAt.UTC().Format(time.RFC3339),
				Fields: []DiscordField{
					{Name: "Source IP", Value: report.SrcIP, Inline: true},
					{Name: "Confidence", Value: fmt.Sprintf("%d%%", report.Confidence), Inline: true},
					{Name: "Attack Path", Value: attackPathStr},
					{Name: "MITRE ATT&CK", Value: mitreStr},
					{Name: "Evidence", Value: evidenceStr},
					{Name: "Recommended Actions", Value: recommendationsStr},
				},
				Footer: &DiscordFooter{Text: fmt.Sprintf("Session: %s", report.SessionID)},
			},
		},
	}

	// Logging terminal verification output context
	fmt.Printf("\n--- [DISPATCHING TELEMETRY ALERT] ---\n%s\n------------------------------------\n", payload.Embeds[0].Title)

	bodyBytes, _ := json.Marshal(payload)

	// Asynchronous fire-and-forget payload delivery to keep loop iterations non-blocking
	go func() {
		req, err := http.NewRequest("POST", DiscordWebhook, bytes.NewBuffer(bodyBytes))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
		}
	}()
}
