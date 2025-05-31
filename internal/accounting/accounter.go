package accounting

import (
	"fmt"
)

type Accounter interface {
	SendAccountingData(data *AccountingData) error
	Close() error
}

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

func NewAccounter(config map[string]interface{}) (Accounter, error) {
	middlewareType, ok := config["type"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid middleware type config")
	}

	switch middlewareType {
	case "file":
		return NewFileAccounter()

	case "kafka":
		brokers, ok := config["brokers"].([]string)
		if !ok {
			return nil, fmt.Errorf("invalid kafka brokers config")
		}
		topic, ok := config["topic"].(string)
		if !ok {
			return nil, fmt.Errorf("invalid kafka topic config")
		}
		return NewKafkaAccounter(brokers, topic)

	case "nats":
		url, ok := config["url"].(string)
		if !ok {
			return nil, fmt.Errorf("invalid nats url config")
		}
		subject, ok := config["subject"].(string)
		if !ok {
			return nil, fmt.Errorf("invalid nats subject config")
		}
		return NewNatsAccounter(url, subject)

	default:
		return nil, fmt.Errorf("unsupported middleware type: %s", middlewareType)
	}
}
