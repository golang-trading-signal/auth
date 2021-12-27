package main

import (
	"gitlab.com/bshadmehr76/vgang-auth/app"
	"gitlab.com/bshadmehr76/vgang-auth/logger"
)

func main() {
	logger.Info("Starting the application")
	app.Start()
}
