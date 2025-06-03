package exporter

import (
	"encoding/json"
	"fmt"
	"gradius/internal/logger"

	"github.com/nats-io/nats.go"
	"github.com/sirupsen/logrus"
)

type NatsMessageExporter struct {
	conn    *nats.Conn
	subject string
	log     *logrus.Logger
}

func NewNatsMessageExporter(url, subject string) (*NatsMessageExporter, error) {
	log := logger.GetLogger()

	log.WithFields(logrus.Fields{
		"url":     url,
		"subject": subject,
	}).Info("Connecting to NATS")

	conn, err := nats.Connect(url)
	if err != nil {
		log.WithError(err).Error("Failed to connect to NATS")
		return nil, fmt.Errorf("failed to connect to NATS: %w", err)
	}

	log.Info("Successfully connected to NATS")
	return &NatsMessageExporter{
		conn:    conn,
		subject: subject,
		log:     log,
	}, nil
}

// SendAuthingData sends authentication data to NATS
func (n *NatsMessageExporter) SendAuthingData(data *AuthingData) error {
	logger := n.log.WithFields(logrus.Fields{
		"user_name": data.UserName,
		"nas_ip":    data.NASIPAddr,
	})

	jsonData, err := json.Marshal(data)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal authing data")
		return fmt.Errorf("failed to marshal authing data: %w", err)
	}

	err = n.conn.Publish(n.subject, jsonData)
	if err != nil {
		logger.WithError(err).Error("Failed to publish message to NATS")
		return fmt.Errorf("failed to publish message to NATS: %w", err)
	}

	logger.Debug("Successfully sent authing data to NATS")
	return nil
}

// SendAccountingData sends accounting data to NATS
func (n *NatsMessageExporter) SendAccountingData(data *AccountingData) error {
	logger := n.log.WithFields(logrus.Fields{
		"user_name":  data.UserName,
		"event_type": data.EventType,
		"session_id": data.AcctSessionID,
		"nas_ip":     data.NASIPAddr,
	})

	jsonData, err := json.Marshal(data)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal accounting data")
		return fmt.Errorf("failed to marshal accounting data: %w", err)
	}

	err = n.conn.Publish(n.subject, jsonData)
	if err != nil {
		logger.WithError(err).Error("Failed to publish message to NATS")
		return fmt.Errorf("failed to publish message to NATS: %w", err)
	}

	logger.Debug("Successfully sent accounting data to NATS")
	return nil
}

func (n *NatsMessageExporter) Close() error {
	n.conn.Close()
	return nil
}
