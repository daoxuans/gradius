package accounting

import (
	"encoding/json"
	"fmt"
	"gradius/internal/logger"

	"github.com/sirupsen/logrus"
)

type FileAccounter struct {
	log *logrus.Logger
}

func NewFileAccounter() (*FileAccounter, error) {
	log := logger.GetLogger()
	log.Info("Initializing File Accounter for local logging")

	return &FileAccounter{
		log: log,
	}, nil
}

func (f *FileAccounter) SendAccountingData(data *AccountingData) error {
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

func (f *FileAccounter) Close() error {
	return nil
}
