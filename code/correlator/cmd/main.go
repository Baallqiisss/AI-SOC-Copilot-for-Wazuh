package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// markCorrelated updates the alert's status to true so it isn't fetched again.
func markCorrelated(ctx context.Context, alerts *mongo.Collection, id interface{}) {
	if id == nil {
		return
	}
	_, _ = alerts.UpdateOne(
		ctx,
		bson.M{"_id": id},
		bson.M{"$set": bson.M{"correlated": true}},
	)
}

// getSeverityTier maps numerical scores into distinct string alerts for AI routing.
func getSeverityTier(score int) string {
	if score <= 15 {
		return "low"
	} else if score <= 30 {
		return "medium"
	} else if score <= 45 {
		return "high"
	}
	return "critical"
}

func main() {
	ctx := context.Background()

	// 1. Connect to MongoDB
	client, err := mongo.Connect(
		ctx,
		options.Client().ApplyURI("mongodb://localhost:27017"),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if dErr := client.Disconnect(ctx); dErr != nil {
			log.Printf("Error disconnecting from MongoDB: %v", dErr)
		}
	}()

	db := client.Database("wazuh")
	alerts := db.Collection("alerts")
	sessions := db.Collection("sessions")

	// Dynamic Strategy: Categorized Rule Sets
	initialAccessRules := map[string]bool{
		"100510": true, "100520": true, "100530": true, // docker SQLi chain
		"100003": true, "100004": true, "100005": true, "100010": true, // vuln_lab: login_failed/brute-force/login_success/sqli_attempt
	}
	discoveryRules := map[string]bool{
		"101101": true, "101102": true, // docker discovery
		"100001": true, "100002": true, "100014": true, // vuln_lab: recon/sensitive endpoint/path traversal
	}
	executionRules := map[string]bool{
		"101200": true, "101201": true, "101301": true, "101302": true, "101303": true, // docker execution
		"100011": true, "100012": true, "100020": true, "100021": true, // vuln_lab: cmd injection/ssti/rce/reverse_shell
	}
	persistenceRules := map[string]bool{
		"101400": true, "101401": true, "101402": true, // docker persistence
		"100013": true, // vuln_lab: suspicious file upload (web shell)
	}

	// Combined list for early filtering optimization
	interestingRules := map[string]bool{}
	for k := range initialAccessRules { interestingRules[k] = true }
	for k := range discoveryRules     { interestingRules[k] = true }
	for k := range executionRules     { interestingRules[k] = true }
	for k := range persistenceRules   { interestingRules[k] = true }

	// Active session cache variables
	var latestSessionID primitive.ObjectID
	var hasLatestSession bool

	fmt.Println("Wazuh correlator daemon started successfully with Dynamic AI Context Scoring.")

	// 2. Continuous Daemon Loop
	for {
		processedCount := 0

		// Expire old sessions (10-minute timeout)
		_, err = sessions.UpdateMany(
			ctx,
			bson.M{
				"status": "active",
				"last_seen": bson.M{
					"$lt": time.Now().Add(-10 * time.Minute),
				},
			},
			bson.M{
				"$set": bson.M{
					"status": "closed",
				},
			},
		)
		if err != nil {
			log.Printf("Error expiring sessions: %v\n", err)
		}

		hasLatestSession = false

		// Stream uncorrelated alerts
		cursor, err := alerts.Find(
			ctx,
			bson.M{"correlated": bson.M{"$ne": true}},
		)
		if err != nil {
			log.Printf("Cursor find error: %v\n", err)
			time.Sleep(2 * time.Second)
			continue
		}

		for cursor.Next(ctx) {
			var doc bson.M
			if err := cursor.Decode(&doc); err != nil {
				continue
			}

			processedCount++
			docID := doc["_id"]

			decoderMap, ok := doc["decoder"].(bson.M)
			if !ok {
				markCorrelated(ctx, alerts, docID)
				continue
			}
			decoderName, _ := decoderMap["name"].(string)

			ruleMap, ok := doc["rule"].(bson.M)
			if !ok {
				markCorrelated(ctx, alerts, docID)
				continue
			}
			ruleID, _ := ruleMap["id"].(string)
			description, _ := ruleMap["description"].(string)

			// Early Filter Validation
			if !interestingRules[ruleID] {
				markCorrelated(ctx, alerts, docID)
				continue
			}

			// Defensive Type Parsing for Wazuh Rule Levels (Handles multiple numeric types gracefully)
			var ruleLevel int
			if levelVal, exists := ruleMap["level"]; exists {
				switch v := levelVal.(type) {
				case int32:
					ruleLevel = int(v)
				case int64:
					ruleLevel = int(v)
				case float64:
					ruleLevel = int(v)
				case int:
					ruleLevel = v
				default:
					ruleLevel = 1 // Basic minimal score fallback
				}
			}

			// Parse alert timestamp
			var alertTime time.Time
			if tsStr, ok := doc["timestamp"].(string); ok {
				parsedTime, err := time.Parse("2006-01-02T15:04:05.000-0700", tsStr)
				if err == nil {
					alertTime = parsedTime
				} else {
					alertTime = time.Now()
				}
			} else {
				alertTime = time.Now()
			}

		// Extract MITRE ATT&CK technique labels (ID — Technique) from rule
		var mitreLabels []string
		if mitreMap, ok := ruleMap["mitre"].(bson.M); ok {
			ids, _ := mitreMap["id"].(bson.A)
			techs, _ := mitreMap["technique"].(bson.A)
			for i := 0; i < len(ids) && i < len(techs); i++ {
				idStr, _ := ids[i].(string)
				techStr, _ := techs[i].(string)
				if idStr != "" && techStr != "" {
					mitreLabels = append(mitreLabels, idStr+" — "+techStr)
				} else if idStr != "" {
					mitreLabels = append(mitreLabels, idStr)
				}
			}
		}

		event := bson.M{
			"timestamp":   doc["timestamp"],
			"rule_id":     ruleID,
			"description": description,
			"decoder":     decoderName,
			"level":       ruleLevel,
			"mitre":       mitreLabels,
		}

			var updatedSession bson.M
			sessionFound := false

			switch decoderName {

			case "docker_dvwa":
				data, ok := doc["data"].(bson.M)
				if !ok {
					markCorrelated(ctx, alerts, docID)
					continue
				}
				srcIP, ok := data["srcip"].(string)
				if !ok {
					markCorrelated(ctx, alerts, docID)
					continue
				}

				// Build atomic MongoDB operator changes
				setFields := bson.M{"last_seen": alertTime}
				if initialAccessRules[ruleID] { setFields["initial_access"] = true }
				if discoveryRules[ruleID]     { setFields["discovery"] = true }
				if executionRules[ruleID]     { setFields["execution"] = true }
				if persistenceRules[ruleID]   { setFields["persistence"] = true }

				err := sessions.FindOneAndUpdate(
					ctx,
					bson.M{
						"src_ip": srcIP,
						"status": "active",
					},
					bson.M{
						"$setOnInsert": bson.M{
							"session_id":     uuid.New().String(),
							"src_ip":         srcIP,
							"status":         "active",
							"severity":       "low", // Evaluated dynamically below
							"start_time":     alertTime,
							"initial_access": false,
							"discovery":      false,
							"execution":      false,
							"persistence":    false,
						},
						"$set": setFields,
						"$inc": bson.M{
							"severity_score": ruleLevel,
							"event_count":    1,
						},
						"$push": bson.M{
							"events": event,
						},
					},
					options.FindOneAndUpdate().SetUpsert(true).SetReturnDocument(options.After),
				).Decode(&updatedSession)

				if err == nil {
					sessionFound = true
					if id, ok := updatedSession["_id"].(primitive.ObjectID); ok {
						latestSessionID = id
						hasLatestSession = true
					}
				} else {
					fmt.Println("Web session processing error:", err)
				}

			case "json":
			// Vuln Lab app: JSON-decoded alerts carrying src_ip in data
			data, ok := doc["data"].(bson.M)
			if !ok {
				markCorrelated(ctx, alerts, docID)
				continue
			}
			srcIP, ok := data["src_ip"].(string)
			if !ok {
				markCorrelated(ctx, alerts, docID)
				continue
			}

			setFields := bson.M{"last_seen": alertTime}
			if initialAccessRules[ruleID] { setFields["initial_access"] = true }
			if discoveryRules[ruleID]     { setFields["discovery"] = true }
			if executionRules[ruleID]     { setFields["execution"] = true }
			if persistenceRules[ruleID]   { setFields["persistence"] = true }

			err := sessions.FindOneAndUpdate(
				ctx,
				bson.M{
					"src_ip": srcIP,
					"status": "active",
				},
				bson.M{
					"$setOnInsert": bson.M{
						"session_id":  uuid.New().String(),
						"src_ip":      srcIP,
						"status":      "active",
						"severity":    "low",
						"start_time":  alertTime,
					},
					"$set": setFields,
					"$inc": bson.M{
						"severity_score": ruleLevel,
						"event_count":    1,
					},
					"$push": bson.M{
						"events": event,
					},
				},
				options.FindOneAndUpdate().SetUpsert(true).SetReturnDocument(options.After),
			).Decode(&updatedSession)

			if err == nil {
				sessionFound = true
				if id, ok := updatedSession["_id"].(primitive.ObjectID); ok {
					latestSessionID = id
					hasLatestSession = true
				}
			} else {
				fmt.Println("Vuln lab session processing error:", err)
			}

		case "auditd":
				if !hasLatestSession {
					var fallbackSession bson.M
					err := sessions.FindOne(
						ctx,
						bson.M{"status": "active"},
						options.FindOne().SetSort(bson.M{"last_seen": -1}),
					).Decode(&fallbackSession)

					if err == nil {
						if id, ok := fallbackSession["_id"].(primitive.ObjectID); ok {
							latestSessionID = id
							hasLatestSession = true
						}
					}
				}

				if hasLatestSession {
					setFields := bson.M{"last_seen": alertTime}
					if initialAccessRules[ruleID] { setFields["initial_access"] = true }
					if discoveryRules[ruleID]     { setFields["discovery"] = true }
					if executionRules[ruleID]     { setFields["execution"] = true }
					if persistenceRules[ruleID]   { setFields["persistence"] = true }

					err = sessions.FindOneAndUpdate(
						ctx,
						bson.M{"_id": latestSessionID},
						bson.M{
							"$set": setFields,
							"$inc": bson.M{
								"severity_score": ruleLevel,
								"event_count":    1,
							},
							"$push": bson.M{
								"events": event,
							},
						},
						options.FindOneAndUpdate().SetReturnDocument(options.After),
					).Decode(&updatedSession)

					if err == nil {
						sessionFound = true
					} else {
						fmt.Println("Audit host session increment error:", err)
					}
				}
			}

			// Dynamic Tier Optimization & AI Condition Tracking
			if sessionFound {
				var finalScore int
				if scoreVal, exists := updatedSession["severity_score"]; exists {
					switch s := scoreVal.(type) {
					case int32:   finalScore = int(s)
					case int64:   finalScore = int(s)
					case float64: finalScore = int(s)
					case int:     finalScore = s
					}
				}

				severityTier := getSeverityTier(finalScore)

				// Normalize text tier update alongside numerical calculations
				_, _ = sessions.UpdateOne(
					ctx,
					bson.M{"_id": updatedSession["_id"]},
					bson.M{"$set": bson.M{"severity": severityTier}},
				)

				// AI Hook Guardrail: Intercept high/critical sessions for token containment
				if severityTier == "high" || severityTier == "critical" {
					fmt.Printf("[TRIGGER AI] Session Alert! ID: %v | Tier: %s | Score: %d\n",
						updatedSession["session_id"], severityTier, finalScore)
					// TODO: Add your message broker or API webhook call to the LLM agent right here.
				}
			}

			markCorrelated(ctx, alerts, docID)
		}

		cursor.Close(ctx)

		// Calculate remaining uncorrelated queue
		remainingCount, _ := alerts.CountDocuments(
			ctx,
			bson.M{"correlated": bson.M{"$ne": true}},
		)

		fmt.Printf("processed=%d active_uncorrelated=%d\n", processedCount, remainingCount)
		time.Sleep(2 * time.Second)
	}
}
