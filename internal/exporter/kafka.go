package exporter

import (
	"encoding/json"
	"fmt"
	"gradius/internal/logger"

	"github.com/IBM/sarama"
	"github.com/sirupsen/logrus"
)

type KafkaMessageExporter struct {
	producer sarama.SyncProducer
	topic    string
	log      *logrus.Logger
}

func NewKafkaMessageExporter(brokers []string, topic string) (*KafkaMessageExporter, error) {
	log := logger.GetLogger()

	config := sarama.NewConfig()
	config.Producer.RequiredAcks = sarama.WaitForAll
	config.Producer.Retry.Max = 5
	config.Producer.Return.Successes = true

	log.WithFields(logrus.Fields{
		"brokers": brokers,
		"topic":   topic,
	}).Info("Connecting to Kafka")

	producer, err := sarama.NewSyncProducer(brokers, config)
	if err != nil {
		log.WithError(err).Error("Failed to create Kafka producer")
		return nil, fmt.Errorf("failed to create kafka producer: %w", err)
	}

	log.Info("Successfully connected to Kafka")
	return &KafkaMessageExporter{
		producer: producer,
		topic:    topic,
		log:      log,
	}, nil
}

// SendAuthingData sends authentication data to Kafka
func (k *KafkaMessageExporter) SendAuthingData(data *AuthingData) error {
	logger := k.log.WithFields(logrus.Fields{
		"user_name": data.UserName,
		"nas_ip":    data.NASIPAddr,
	})

	jsonData, err := json.Marshal(data)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal authing data")
		return fmt.Errorf("failed to marshal authing data: %w", err)
	}

	msg := &sarama.ProducerMessage{
		Topic: k.topic,
		Value: sarama.StringEncoder(jsonData),
		Key:   sarama.StringEncoder(data.UserName),
	}

	partition, offset, err := k.producer.SendMessage(msg)
	if err != nil {
		logger.WithError(err).Error("Failed to send message to Kafka")
		return fmt.Errorf("failed to send message to kafka: %w", err)
	}

	logger.WithFields(logrus.Fields{
		"partition": partition,
		"offset":    offset,
	}).Debug("Successfully sent authing data to Kafka")

	return nil
}

// SendAccountingData sends accounting data to Kafka

func (k *KafkaMessageExporter) SendAccountingData(data *AccountingData) error {
	logger := k.log.WithFields(logrus.Fields{
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

	msg := &sarama.ProducerMessage{
		Topic: k.topic,
		Value: sarama.StringEncoder(jsonData),
		Key:   sarama.StringEncoder(data.AcctSessionID),
	}

	partition, offset, err := k.producer.SendMessage(msg)
	if err != nil {
		logger.WithError(err).Error("Failed to send message to Kafka")
		return fmt.Errorf("failed to send message to kafka: %w", err)
	}

	logger.WithFields(logrus.Fields{
		"partition": partition,
		"offset":    offset,
	}).Debug("Successfully sent accounting data to Kafka")

	return nil
}

func (k *KafkaMessageExporter) Close() error {
	if err := k.producer.Close(); err != nil {
		k.log.WithError(err).Error("Failed to close Kafka producer")
		return fmt.Errorf("failed to close kafka producer: %w", err)
	}
	return nil
}
