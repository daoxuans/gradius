package main

import (
	"fmt"
	"gradius/internal/accounting"
	"gradius/internal/auth"
	"gradius/internal/logger"
	"gradius/pkg/radius"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/viper"
)

func main() {
	// Load configuration
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("/etc/gradius/")
	viper.AddConfigPath("$HOME/.gradius")
	viper.AddConfigPath("./config")

	if err := viper.ReadInConfig(); err != nil {
		fmt.Printf("Error reading config file: %s\n", err)
		os.Exit(1)
	}

	// Initialize logger
	err := logger.Init(
		viper.GetString("logging.file"),
		viper.GetString("logging.level"),
		viper.GetInt("logging.max_size"),
		viper.GetInt("logging.max_backups"),
	)
	if err != nil {
		fmt.Printf("Error initializing logger: %s\n", err)
		os.Exit(1)
	}

	log := logger.GetLogger()

	// Initialize Redis authenticator
	authenticator, err := auth.NewRedisAuthenticator(
		viper.GetString("redis.host"),
		viper.GetString("redis.port"),
		viper.GetString("redis.password"),
		viper.GetInt("redis.db"),
	)
	if err != nil {
		log.Fatalf("Error initializing Redis authenticator: %s", err)
	}

	// accounter configuration
	accountingConfig := make(map[string]interface{})
	accountingType := viper.GetString("accounting_export.type")
	accountingConfig["type"] = accountingType

	switch accountingType {
	case "kafka":
		accountingConfig["brokers"] = viper.GetStringSlice("accounting_export.kafka.brokers")
		accountingConfig["topic"] = viper.GetString("accounting_export.kafka.topic")
	case "nats":
		accountingConfig["url"] = viper.GetString("accounting_export.nats.url")
		accountingConfig["subject"] = viper.GetString("accounting_export.nats.subject")
	case "file":
		log.Info("Using file logging for accounting data")
	default:
		log.Fatalf("Unsupported messaging middleware type: %s", accountingType)
	}

	// Initialize accounter
	accounter, err := accounting.NewAccounter(accountingConfig)
	if err != nil {
		log.Fatalf("Error initializing accounter: %s", err)
	}

	// Initialize NAS IP validator
	nasValidator, err := auth.NewNASIPValidator(viper.GetStringSlice("server.nas_networks"))
	if err != nil {
		log.Fatalf("Error initializing NAS IP validator: %s", err)
	}

	secret := viper.GetString("server.secret")
	if secret == "" {
		log.Fatal("RADIUS server secret is not configured")
	}

	// Create and start RADIUS server
	server := radius.NewServer(
		secret,
		authenticator,
		accounter,
		nasValidator,
	)

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Info("Shutting down server...")
		if err := server.Shutdown(); err != nil {
			log.Errorf("Error during shutdown: %v", err)
		}
		os.Exit(0)
	}()

	// Start server
	authAddr := fmt.Sprintf(":%d", viper.GetInt("server.auth_port"))
	acctAddr := fmt.Sprintf(":%d", viper.GetInt("server.acct_port"))
	adminAddr := fmt.Sprintf(":%d", viper.GetInt("server.admin_port"))

	log.Infof("Starting RADIUS server (auth: %s, acct: %s, admin: %s)", authAddr, acctAddr, adminAddr)
	if err := server.ListenAndServe(authAddr, acctAddr, adminAddr); err != nil {
		log.Fatalf("Server error: %s", err)
	}
}
