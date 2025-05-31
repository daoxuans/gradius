package accounting

import (
	"encoding/json"
	"fmt"
	"gradius/internal/logger"

	"github.com/nats-io/nats.go"
	"github.com/sirupsen/logrus"
)

type NatsAccounter struct {
	conn    *nats.Conn
	subject string
	log     *logrus.Logger
}

func NewNatsAccounter(url, subject string) (*NatsAccounter, error) {
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
	return &NatsAccounter{
		conn:    conn,
		subject: subject,
		log:     log,
	}, nil
}

func (n *NatsAccounter) SendAccountingData(data *AccountingData) error {
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

func (n *NatsAccounter) Close() error {
	n.conn.Close()
	return nil
}
