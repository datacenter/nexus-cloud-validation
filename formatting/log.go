package formatting

import (
	"log"
	"os"
	"strings"
)

type LevelLogger struct {
	loggingLevel int
}

func (m *LevelLogger) Init() {
	switch level := strings.ToUpper(os.Getenv("LOG_LEVEL")); level {
	case "TRACE":
		m.loggingLevel = 3
	case "DEBUG":
		m.loggingLevel = 2
	case "INFO":
		m.loggingLevel = 1
	default:
		m.loggingLevel = 0
	}
}

func (m *LevelLogger) SetLevel(level int) {
	m.loggingLevel = level
}

func (m *LevelLogger) Trace(msg string) {
	if m.loggingLevel == 3 {
		log.Printf("[TRACE] %s", msg)
	}
}

func (m *LevelLogger) Debug(msg string) {
	if m.loggingLevel >= 2 {
		log.Printf("[DEBUG] %s", msg)
	}
}

func (m *LevelLogger) Info(msg string) {
	if m.loggingLevel >= 1 {
		log.Printf("[INFO] %s", msg)
	}
}

func (m *LevelLogger) Error(err error) {
	log.Printf("[ERROR] %s", err)
}

func (m *LevelLogger) Fatal(err error) {
	log.Printf("[FATAL] %s", err)
	os.Exit(1)
}

func (m *LevelLogger) Panic(err error) {
	log.Printf("[PANIC] %s", err)
	panic(err)
}
