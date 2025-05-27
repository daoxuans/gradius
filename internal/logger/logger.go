package logger

import (
	"io"
	"os"

	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

var log *logrus.Logger

func Init(filePath string, level string, maxSize int, maxBackups int) error {
	log = logrus.New()

	// Set log level
	lvl, err := logrus.ParseLevel(level)
	if err != nil {
		return err
	}
	log.SetLevel(lvl)

	// Set log format to JSON
	log.SetFormatter(&logrus.JSONFormatter{})

	// Set up log rotation
	rotator := &lumberjack.Logger{
		Filename:   filePath,
		MaxSize:    maxSize, // MB
		MaxBackups: maxBackups,
		Compress:   true,
	}

	// Write logs to both file and stdout
	mw := io.MultiWriter(os.Stdout, rotator)
	log.SetOutput(mw)

	return nil
}

func GetLogger() *logrus.Logger {
	return log
}
