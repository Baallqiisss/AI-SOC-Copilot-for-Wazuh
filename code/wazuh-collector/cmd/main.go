package main

import (
	"context"
	"encoding/json"
	"log"

	"wazuh-collector/internal"
)

func main() {

	client, err := internal.ConnectMongo()
	if err != nil {
		panic(err)
	}

	db := client.Database("wazuh")

	alerts := db.Collection("alerts")
	rawLogs := db.Collection("raw_logs")

	alertTail, err := internal.NewTail(
		"/var/ossec/logs/alerts/alerts.json",
	)
	if err != nil {
		panic(err)
	}

	rawTail, err := internal.NewTail(
		"/var/ossec/logs/archives/archives.json",
	)
	if err != nil {
		panic(err)
	}

	go func() {

		for line := range alertTail.Lines {

			var doc map[string]interface{}

			if err := json.Unmarshal(
				[]byte(line.Text),
				&doc,
			); err != nil {
				continue
			}

			_, err = alerts.InsertOne(
				context.Background(),
				doc,
			)

			if err == nil {
				log.Println(
					"[ALERT]",
					doc["id"],
				)
			}
		}
	}()

	for line := range rawTail.Lines {

		var doc map[string]interface{}

		if err := json.Unmarshal(
			[]byte(line.Text),
			&doc,
		); err != nil {
			continue
		}

		_, err = rawLogs.InsertOne(
			context.Background(),
			doc,
		)

		if err == nil {
			log.Println(
				"[RAW]",
				doc["id"],
			)
		}
	}
}
