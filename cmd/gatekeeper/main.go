package main

import (
	"flag"
	"log"
	"os"

	"github.com/TOomaAh/GateKeeper/internal/config"
	"github.com/TOomaAh/GateKeeper/internal/gatekeeper"
)

const defaultConfigPath = "./config.yaml"

func main() {
	// Parse command line flags
	configPath := flag.String("config", defaultConfigPath, "Path to configuration file")
	flag.Parse()

	// Load configuration
	cfg, err := config.LoadConfiguration(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Create GateKeeper instance
	gk, err := gatekeeper.NewGateKeeper(cfg)
	if err != nil {
		log.Fatalf("Failed to create GateKeeper: %v", err)
	}

	// Run server
	log.Println("Starting GateKeeper...")
	if err := gk.Run(); err != nil {
		log.Fatalf("Server error: %v", err)
	}

	os.Exit(0)
}
