package log

import (
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

func NewLogrusLogger() *logrus.Logger {
	l := logrus.New()
	l.SetOutput(os.Stdout)
	l.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: time.RFC3339,
		ForceColors:     true,
		DisableColors:   false,
	})
	l.SetLevel(logrus.InfoLevel)
	l.AddHook(NewBroadcastHook())
	return l
}
