package main

import (
	"flag"
	"os"

	"ttl-allow-service/src/internal/server"
)

func main() {
	configFlag := flag.String("config", "", "path to config file")
	flag.Parse()

	configPath := *configFlag
	if configPath == "" {
		configPath = os.Getenv("CONFIG_FILE")
	}
	if configPath == "" {
		configPath = "config.yaml"
	}

	server.Start(configPath)
}
