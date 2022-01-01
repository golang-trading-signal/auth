package main

import (
	"github.com/golang-trading-signal/libs/logger"
	"gitlab.com/bshadmehr76/vgang-auth/app"
)

func main() {
	logger.Info("Starting the application")
	app.Start()
}
