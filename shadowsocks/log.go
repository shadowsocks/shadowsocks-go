package shadowsocks

import (
	"os"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	// Logger used to out put the log, zap logger is fast and efficiency
	Logger *zap.Logger
	// Level can be set into Debug Info Error, and Error level is used by default
	Level string
)

// SetLogger will generate a zap logger with given level for log output
func SetLogger() {
	var lv = zap.NewAtomicLevel()
	var encoder zapcore.Encoder
	var output zapcore.WriteSyncer
	output = zapcore.AddSync(os.Stdout)

	switch Level {
	case "debug", "Debug", "DEBUG":
		lv.SetLevel(zap.DebugLevel)
	case "info", "Info", "INFO":
		lv.SetLevel(zap.InfoLevel)
	case "error", "Error", "ERROR":
		lv.SetLevel(zap.ErrorLevel)
	case "fatal", "Fatal", "FATAL":
		lv.SetLevel(zap.FatalLevel)
	default:
		lv.SetLevel(zap.ErrorLevel)
	}

	timeEncoder := func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
		enc.AppendString(t.Local().Format("2006-01-02 15:04:05"))
	}

	encoderCfg := zapcore.EncoderConfig{
		NameKey:        "Name",
		StacktraceKey:  "Stack",
		MessageKey:     "Message",
		LevelKey:       "Level",
		TimeKey:        "TimeStamp",
		CallerKey:      "Caller",
		EncodeTime:     timeEncoder,
		EncodeLevel:    zapcore.CapitalColorLevelEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	//encoder = zapcore.NewJSONEncoder(encoderCfg)
	encoder = zapcore.NewConsoleEncoder(encoderCfg)

	Logger = zap.New(zapcore.NewCore(encoder, output, lv), zap.AddCaller())
}
