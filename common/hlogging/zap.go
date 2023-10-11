package hlogging

import (
	"fmt"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func NewZapLogger(core zapcore.Core, options ...zap.Option) *zap.Logger {
	return zap.New(core, append([]zap.Option{zap.AddCaller(), zap.AddStacktrace(zap.ErrorLevel)}, options...)...)
}

type HyperchainLogger struct {
	s *zap.SugaredLogger
}

func NewHyperchainLogger(l *zap.Logger, options ...zap.Option) *HyperchainLogger {
	return &HyperchainLogger{
		s: l.WithOptions(append(options, zap.AddCallerSkip(1))...).Sugar(),
	}
}

func (hl *HyperchainLogger) Debug(args ...interface{}) { hl.s.Debug(formatArgs(args)) }
func (hl *HyperchainLogger) Debugf(template string, args ...interface{}) {
	hl.s.Debugf(template, args...)
}
func (hl *HyperchainLogger) Debugw(msg string, kvs ...interface{}) { hl.s.Debugw(msg, kvs...) }

func (hl *HyperchainLogger) Info(args ...interface{}) { hl.s.Info(formatArgs(args)) }
func (hl *HyperchainLogger) Infof(template string, args ...interface{}) {
	hl.s.Infof(template, args...)
}
func (hl *HyperchainLogger) Infow(msg string, kvs ...interface{}) { hl.s.Infow(msg, kvs...) }

func (hl *HyperchainLogger) Warn(args ...interface{}) { hl.s.Warn(formatArgs(args)) }
func (hl *HyperchainLogger) Warnf(template string, args ...interface{}) {
	hl.s.Warnf(template, args...)
}
func (hl *HyperchainLogger) Warnw(msg string, kvs ...interface{}) { hl.s.Warnw(msg, kvs...) }

func (hl *HyperchainLogger) Error(args ...interface{}) { hl.s.Error(formatArgs(args)) }
func (hl *HyperchainLogger) Errorf(template string, args ...interface{}) {
	hl.s.Errorf(template, args...)
}
func (hl *HyperchainLogger) Errorw(msg string, kvs ...interface{}) { hl.s.Errorw(msg, kvs...) }

func (hl *HyperchainLogger) Panic(args ...interface{}) { hl.s.Panic(formatArgs(args)) }
func (hl *HyperchainLogger) Panicf(template string, args ...interface{}) {
	hl.s.Panicf(template, args...)
}
func (hl *HyperchainLogger) Panicw(msg string, kvs ...interface{}) { hl.s.Panicw(msg, kvs...) }

func (hl *HyperchainLogger) IsEnabledFor(level zapcore.Level) bool {
	return hl.s.Desugar().Core().Enabled(level)
}

func (hl *HyperchainLogger) With(args ...interface{}) *HyperchainLogger {
	return &HyperchainLogger{s: hl.s.With(args...)}
}

func (hl *HyperchainLogger) Named(name string) *HyperchainLogger {
	return &HyperchainLogger{s: hl.s.Named(name)}
}

func formatArgs(args []interface{}) string {
	return fmt.Sprint(args...)
}
