package exporter

import (
	"fmt"
	"gradius/internal/logger"
)

type MessageExporter interface {
	SendAccountingData(data *AccountingData) error
	SendAuthingData(data *AuthingData) error
	Close() error
}

type AuthingData struct {
	Timestamp        int64  `json:"timestamp"`           // Unix 时间戳（秒）
	UserName         string `json:"user_name"`           // 用户名 => user_name
	FramedIP         string `json:"framed_ip,omitempty"` // 用户分配的 IP 地址
	CallingStationID string `json:"calling_station_id"`  // MAC 地址
	CalledStationID  string `json:"called_station_id"`   // 接入点标识
	NASIPAddr        string `json:"nas_ip"`              // 原 "nas_ip_addr" => nas_ip
	IsSuccess        bool   `json:"success"`             // 是否成功
	FailureReason    string `json:"reason"`              // 失败原因
}

type AccountingData struct {
	EventType        string `json:"event_type"`              // Start/Interim-Update/Stop
	Timestamp        int64  `json:"timestamp"`               // Unix 时间戳（秒）
	EventTimestamp   string `json:"event_timestamp"`         // ISO8601 UTC 时间
	UserName         string `json:"user_name"`               // 用户名 => user_name
	NasIdentifier    string `json:"nas_identifier"`          // NAS 设备标识
	NASIPAddr        string `json:"nas_ip"`                  // 原 "nas_ip_addr" => nas_ip
	AcctSessionID    string `json:"acct_session_id"`         // 会话唯一 ID
	FramedIP         string `json:"framed_ip,omitempty"`     // 用户分配的 IP 地址
	CallingStationID string `json:"calling_station_id"`      // MAC 地址
	CalledStationID  string `json:"called_station_id"`       // 接入点标识
	NasPort          int    `json:"nas_port"`                // NAS 端口号
	NasPortType      string `json:"nas_port_type"`           // 端口类型
	InputOctets      uint32 `json:"input_octets,omitempty"`  // 输入字节数
	OutputOctets     uint32 `json:"output_octets,omitempty"` // 输出字节数
}

func NewMessageExporter(config map[string]interface{}) (MessageExporter, error) {
	middlewareType, ok := config["type"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid middleware type config")
	}

	log := logger.GetLogger()

	switch middlewareType {
	case "file":
		return NewFileMessageExporter()

	case "kafka":
		brokers, ok := config["brokers"].([]string)
		if !ok {
			return nil, fmt.Errorf("invalid kafka brokers config")
		}
		topic, ok := config["topic"].(string)
		if !ok {
			return nil, fmt.Errorf("invalid kafka topic config")
		}

		// Try to connect to Kafka
		exporter, err := NewKafkaMessageExporter(brokers, topic)
		if err != nil {
			log.Warnf("Falling back to file exporter from Kafka")
			return NewFileMessageExporter()
		}
		return exporter, nil

	case "nats":
		url, ok := config["url"].(string)
		if !ok {
			return nil, fmt.Errorf("invalid nats url config")
		}
		subject, ok := config["subject"].(string)
		if !ok {
			return nil, fmt.Errorf("invalid nats subject config")
		}

		// Try to connect to NATS
		exporter, err := NewNatsMessageExporter(url, subject)
		if err != nil {
			log.Warnf("Falling back to file exporter from NATS")
			return NewFileMessageExporter()
		}
		return exporter, nil

	default:
		return nil, fmt.Errorf("unsupported middleware type: %s", middlewareType)
	}
}
