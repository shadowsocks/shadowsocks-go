package shadowsocks

import (
	"os"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	Logger *zap.Logger // Logger used to out put the log, zap logger is fast and efficiency
	Level  string      // Level can be set into Debug Info Error, and Error level is used by default
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
	default:
		lv.SetLevel(zap.ErrorLevel)
	}

	timeEncoder := func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
		enc.AppendString(t.Local().Format("2006-01-02 15:04:05.999999999"))
	}

	encoderCfg := zapcore.EncoderConfig{
		NameKey:        "Name",
		StacktraceKey:  "Stack",
		MessageKey:     "Message",
		LevelKey:       "Level",
		TimeKey:        "TimeStamp",
		CallerKey:      "Caller",
		EncodeTime:     timeEncoder,
		EncodeLevel:    zapcore.CapitalLevelEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	encoder = zapcore.NewJSONEncoder(encoderCfg)

	Logger = zap.New(zapcore.NewCore(encoder, output, lv))
}
