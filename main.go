package main

import (
	"log"

	"posrelayd-noip/internal/app"
	"posrelayd-noip/internal/logger"
)

func main() {
	version := "0.3.5.15"

	logger.Websocket.Infof(
		"POSRelayd-NoIP.v%s starting...", version)

	if err := app.Run(); err != nil {
		logger.Websocket.Errorf(
			"The main thread terminated with the error: \n%s", err)
		log.Fatal(err)
	}
}
