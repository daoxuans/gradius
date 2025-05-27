package accounting

import (
	"encoding/json"
	"fmt"
	"gradius/internal/logger"
	"time"

	"github.com/IBM/sarama"
	"github.com/sirupsen/logrus"
)

type AccountingData struct {
	Username    string    `json:"username"`
	NASIPAddr   string    `json:"nas_ip_addr"`
	SessionID   string    `json:"session_id"`
	StartTime   time.Time `json:"start_time,omitempty"`
	StopTime    time.Time `json:"stop_time,omitempty"`
	BytesIn     uint32    `json:"bytes_in"`
	BytesOut    uint32    `json:"bytes_out"`
	PacketsIn   uint32    `json:"packets_in"`
	PacketsOut  uint32    `json:"packets_out"`
	SessionTime int       `json:"session_time"`
}

type KafkaAccounter struct {
	producer sarama.SyncProducer
	topic    string
	log      *logrus.Logger
}

func NewKafkaAccounter(brokers []string, topic string) (*KafkaAccounter, error) {
	log := logger.GetLogger()

	config := sarama.NewConfig()
	config.Producer.RequiredAcks = sarama.WaitForAll
	config.Producer.Retry.Max = 5
	config.Producer.Return.Successes = true

	// Enable logging
	sarama.Logger = log.WithField("component", "sarama")

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
	return &KafkaAccounter{
		producer: producer,
		topic:    topic,
		log:      log,
	}, nil
}

func (k *KafkaAccounter) SendAccountingData(data *AccountingData) error {
	logger := k.log.WithFields(logrus.Fields{
		"username":    data.Username,
		"session_id":  data.SessionID,
		"nas_ip":      data.NASIPAddr,
		"bytes_in":    data.BytesIn,
		"bytes_out":   data.BytesOut,
		"packets_in":  data.PacketsIn,
		"packets_out": data.PacketsOut,
	})

	jsonData, err := json.Marshal(data)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal accounting data")
		return fmt.Errorf("failed to marshal accounting data: %w", err)
	}

	msg := &sarama.ProducerMessage{
		Topic: k.topic,
		Value: sarama.StringEncoder(jsonData),
		Key:   sarama.StringEncoder(data.SessionID),
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

func (k *KafkaAccounter) Close() error {
	if err := k.producer.Close(); err != nil {
		k.log.WithError(err).Error("Failed to close Kafka producer")
		return fmt.Errorf("failed to close kafka producer: %w", err)
	}
	k.log.Info("Kafka producer closed successfully")
	return nil
}
