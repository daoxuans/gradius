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
	authenticator := auth.NewRedisAuthenticator(
		viper.GetString("redis.host"),
		viper.GetString("redis.port"),
		viper.GetString("redis.password"),
		viper.GetInt("redis.db"),
	)

	// Initialize Kafka accounter
	accounter, err := accounting.NewKafkaAccounter(
		viper.GetStringSlice("kafka.brokers"),
		viper.GetString("kafka.topic"),
	)
	if err != nil {
		log.Fatalf("Error initializing Kafka accounter: %s", err)
	}

	// Initialize NAS IP validator
	nasValidator, err := auth.NewNASIPValidator(viper.GetStringSlice("server.nas_networks"))
	if err != nil {
		log.Fatalf("Error initializing NAS IP validator: %s", err)
	}

	// Create and start RADIUS server
	adminAddr := fmt.Sprintf(":%d", viper.GetInt("server.admin_port"))
	server := radius.NewServer(
		viper.GetString("server.secret"),
		authenticator,
		accounter,
		nasValidator,
		adminAddr,
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
	}()

	// Start server
	authAddr := fmt.Sprintf(":%d", viper.GetInt("server.auth_port"))
	acctAddr := fmt.Sprintf(":%d", viper.GetInt("server.acct_port"))

	log.Infof("Starting RADIUS server (auth: %s, acct: %s)", authAddr, acctAddr)
	if err := server.ListenAndServe(authAddr, acctAddr); err != nil {
		log.Fatalf("Server error: %s", err)
	}
}
