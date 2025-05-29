package auth

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"gradius/internal/logger"
	"strings"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
)

// AuthType represents different authentication methods
type AuthType int

const (
	PAP AuthType = iota
	CHAP
	MAC
)

type RedisAuthenticator struct {
	client *redis.Client
	log    *logrus.Logger
}

func NewRedisAuthenticator(host string, port string, password string, db int) (*RedisAuthenticator, error) {
	log := logger.GetLogger()

	client := redis.NewClient(&redis.Options{
		Addr:     host + ":" + port,
		Password: password,
		DB:       db,
	})

	// Test connection
	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		log.WithError(err).Error("Failed to connect to Redis")
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	log.Info("Connected to Redis successfully")
	return &RedisAuthenticator{
		client: client,
		log:    log,
	}, nil
}

func (r *RedisAuthenticator) ValidateCredentials(username, password string, authType AuthType, chapChallenge, chapResponse []byte) (bool, error) {
	ctx := context.Background()
	logger := r.log.WithFields(logrus.Fields{
		"username":  username,
		"auth_type": authType,
	})

	storedPassword, err := r.client.Get(ctx, "user:"+username).Result()
	if err == redis.Nil {
		logger.Info("User not found")
		return false, nil
	} else if err != nil {
		logger.WithError(err).Error("Redis error while fetching user")
		return false, fmt.Errorf("redis error: %w", err)
	}

	switch authType {
	case PAP:
		logger.Debug("Validating PAP credentials")
		return storedPassword == password, nil
	case CHAP:
		if len(chapChallenge) == 0 || len(chapResponse) == 0 {
			logger.Warn("Invalid CHAP parameters")
			return false, fmt.Errorf("invalid CHAP parameters")
		}
		logger.Debug("Validating CHAP credentials")
		// Calculate expected CHAP response
		h := md5.New()
		h.Write([]byte{chapResponse[0]}) // CHAP ID
		h.Write([]byte(storedPassword))
		h.Write(chapChallenge)
		expected := h.Sum(nil)

		// Compare with actual response (skip ID byte)
		valid := hex.EncodeToString(expected) == hex.EncodeToString(chapResponse[1:])
		if !valid {
			logger.Debug("CHAP validation failed")
		}
		return valid, nil
	default:
		logger.Error("Unsupported authentication type")
		return false, fmt.Errorf("unsupported authentication type")
	}
}

func (r *RedisAuthenticator) ValidateMAC(macAddress string) (bool, error) {
	// Normalize MAC address format (remove separators and convert to lowercase)
	mac := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(macAddress, ":", ""), "-", ""))
	logger := r.log.WithField("mac", mac)

	ctx := context.Background()
	exists, err := r.client.Exists(ctx, "mac:"+mac).Result()
	if err != nil {
		logger.WithError(err).Error("Redis error while checking MAC address")
		return false, fmt.Errorf("redis error: %w", err)
	}

	valid := exists == 1
	if !valid {
		logger.Info("MAC address not authorized")
	}
	return valid, nil
}

func (r *RedisAuthenticator) Close() error {
	if err := r.client.Close(); err != nil {
		r.log.WithError(err).Error("Failed to close Redis client")
		return fmt.Errorf("failed to close redis client: %w", err)
	}
	return nil
}
