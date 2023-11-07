package hlogging

import (
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/11090815/hyperchain/common/hlogging/enc"
	zaplogfmt "github.com/sykesm/zap-logfmt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	DefaultFormat = "%{color:bold}%{level:.4s}%{color:reset} %{color}%{time:2006-01-02 15:04:05} %{id:04x}%{color:reset} [%{module}] %{color}%{longfunc}%{color:reset} -> %{message}"
	defaultLevel  = zapcore.InfoLevel
)

const (
	ShortFuncFormat = "%{color:bold}%{level:.4s}%{color:reset} %{color}%{time:2006-01-02 15:04:05} %{id:04x}%{color:reset} [%{module}] %{color}%{shortfunc}%{color:reset} -> %{message}"
)

type Config struct {
	Format  string
	LogSpec string
	Writer  io.Writer
}

type Logging struct {
	*LoggerLevels
	mutex          sync.RWMutex
	encoding       Encoding
	encoderConfig  zapcore.EncoderConfig
	multiFormatter *enc.MultiFormatter
	writer         zapcore.WriteSyncer
	observer       Observer
}

func NewLogging(c Config) (*Logging, error) {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.NameKey = "name"

	l := &Logging{
		LoggerLevels: &LoggerLevels{
			defaultLevel: defaultLevel,
		},
		encoderConfig:  encoderConfig,
		multiFormatter: enc.NewMultiFormatter(),
	}

	if err := l.Apply(c); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *Logging) ZapLogger(name string) *zap.Logger {
	if !isValidLoggerName(name) {
		panic(fmt.Sprintf("invalid logger name: %s", name))
	}

	l.mutex.RLock()
	core := &core{
		LevelEnabler: l.LoggerLevels,
		Levels:       l.LoggerLevels,
		Encoders: map[Encoding]zapcore.Encoder{
			JSON:    zapcore.NewJSONEncoder(l.encoderConfig),
			CONSOLE: enc.NewFormatterEncoder(l.multiFormatter),
			LOGFMT:  zaplogfmt.NewEncoder(l.encoderConfig),
		},
		Selector: l,
		Output:   l,
		Observer: l,
	}
	l.mutex.RUnlock()

	return NewZapLogger(core).Named(name)
}

func (l *Logging) Logger(name string) *HyperchainLogger {
	zl := l.ZapLogger(name)
	return NewHyperchainLogger(zl)
}

func (l *Logging) Check(e zapcore.Entry, ce *zapcore.CheckedEntry) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if l.observer != nil {
		l.observer.Check(e, ce)
	}
}

func (l *Logging) WriteEntry(e zapcore.Entry, fields []zapcore.Field) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if l.observer != nil {
		l.observer.WriteEntry(e, fields)
	}
}

func (l *Logging) Encoding() Encoding {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.encoding
}

func (l *Logging) Sync() error {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	return l.writer.Sync()
}

func (l *Logging) Write(b []byte) (int, error) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	return l.writer.Write(b)
}

func (l *Logging) SetObserver(o Observer) Observer {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	old := l.observer
	l.observer = o
	return old
}

func (l *Logging) SetWriter(w io.Writer) io.Writer {
	var ws zapcore.WriteSyncer

	switch t := w.(type) {
	case *os.File:
		ws = zapcore.Lock(t) // Lock 将 WriteSyncer 包装在一个互斥体中，使其可以安全并发使用。特别是，*os.Files 在使用前必须锁定。
	case zapcore.WriteSyncer:
		ws = t
	default:
		ws = zapcore.AddSync(w) // AddSync 将 io.Writer 转换为 WriteSyncer。它试图做到智能化：如果 io.Writer 的具体类型实现了 WriteSyncer，我们将使用现有的 Sync 方法。如果没有，我们将添加一个无操作的 Sync.Writer 方法。
	}

	l.mutex.Lock()
	defer l.mutex.Unlock()

	old := l.writer
	l.writer = ws

	return old
}

func (l *Logging) SetFormat(format string) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	if format == "" {
		format = DefaultFormat
	}

	if format == "json" {
		l.encoding = JSON
		return nil
	}

	if format == "logfmt" {
		l.encoding = LOGFMT
		return nil
	}

	formatters, err := enc.ParseFormat(format)
	if err != nil {
		return err
	}

	l.multiFormatter.SetFormatters(formatters)
	l.encoding = CONSOLE

	return nil
}

func (l *Logging) Apply(c Config) error {
	if err := l.SetFormat(c.Format); err != nil {
		return err
	}

	if c.LogSpec == "" {
		c.LogSpec = os.Getenv("HYPERCHAIN_LOGGING_SPEC")
	}

	if c.LogSpec == "" {
		c.LogSpec = defaultLevel.String()
	}

	if err := l.LoggerLevels.ActivateSpec(c.LogSpec); err != nil {
		return err
	}

	if c.Writer == nil {
		c.Writer = os.Stderr
	}
	l.SetWriter(c.Writer)

	return nil
}
