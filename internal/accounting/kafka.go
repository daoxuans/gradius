package accounting

import (
	"encoding/json"
	"fmt"
	"gradius/internal/logger"

	"github.com/IBM/sarama"
	"github.com/sirupsen/logrus"
)

// accounting.AccountingData 定义文件：kafka.go
type AccountingData struct {
	EventType        string `json:"event_type"`          // Start/Interim-Update/Stop
	Timestamp        int64  `json:"timestamp"`           // Unix 时间戳（秒）
	EventTimestamp   string `json:"event_timestamp"`     // ISO8601 UTC 时间
	UserName         string `json:"user_name"`           // 用户名 => user_name
	NasIdentifier    string `json:"nas_identifier"`      // NAS 设备标识
	NASIPAddr        string `json:"nas_ip"`              // 原 "nas_ip_addr" => nas_ip
	AcctSessionID    string `json:"acct_session_id"`     // 会话唯一 ID
	FramedIP         string `json:"framed_ip,omitempty"` // 用户分配的 IP 地址
	CallingStationID string `json:"calling_station_id"`  // MAC 地址
	CalledStationID  string `json:"called_station_id"`   // 接入点标识
	NasPort          int    `json:"nas_port"`            // NAS 端口号
	NasPortType      string `json:"nas_port_type"`       // 端口类型

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
	// sarama.Logger = log.WithField("component", "sarama")

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

func (k *KafkaAccounter) Close() error {
	if err := k.producer.Close(); err != nil {
		k.log.WithError(err).Error("Failed to close Kafka producer")
		return fmt.Errorf("failed to close kafka producer: %w", err)
	}
	return nil
}
