package internal

import "time"

type Event struct {
	Timestamp   string `bson:"timestamp"`
	RuleID      string `bson:"rule_id"`
	Description string `bson:"description"`
	Decoder     string `bson:"decoder"`
}

type Session struct {
	SessionID string    `bson:"session_id"`
	SrcIP     string    `bson:"src_ip"`
	AgentID   string    `bson:"agent_id"`

	Status    string    `bson:"status"`
	Severity  string    `bson:"severity"`

	StartTime time.Time `bson:"start_time"`
	LastSeen  time.Time `bson:"last_seen"`

	Events []Event `bson:"events"`
}
