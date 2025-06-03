package exporter

import (
	"encoding/json"
	"fmt"
	"gradius/internal/logger"

	"github.com/sirupsen/logrus"
)

type FileMessageExporter struct {
	log *logrus.Logger
}

func NewFileMessageExporter() (*FileMessageExporter, error) {
	log := logger.GetLogger()
	log.Info("Initializing File MessageLogger for local logging")

	return &FileMessageExporter{
		log: log,
	}, nil
}

func (f *FileMessageExporter) SendAuthingData(data *AuthingData) error {
	logger := f.log.WithFields(logrus.Fields{
		"user_name": data.UserName,
		"nas_ip":    data.NASIPAddr,
	})

	jsonData, err := json.Marshal(data)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal authing data")
		return fmt.Errorf("failed to marshal authing data: %w", err)
	}

	logger.WithField("authing_data", string(jsonData)).Info("Authing data logged to file")
	return nil
}

func (f *FileMessageExporter) SendAccountingData(data *AccountingData) error {
	logger := f.log.WithFields(logrus.Fields{
		"user_name":  data.UserName,
		"event_type": data.EventType,
		"session_id": data.AcctSessionID,
		"nas_ip":     data.NASIPAddr,
		"client_ip":  data.FramedIP,
	})

	jsonData, err := json.Marshal(data)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal accounting data")
		return fmt.Errorf("failed to marshal accounting data: %w", err)
	}

	logger.WithField("accounting_data", string(jsonData)).Info("Accounting data logged to file")

	return nil
}

func (f *FileMessageExporter) Close() error {
	return nil
}
