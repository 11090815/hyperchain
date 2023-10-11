package hlogging

import "io"

var Global *Logging

func init() {
	logging, err := NewLogging(Config{})
	if err != nil {
		panic(err)
	}

	Global = logging
}

func Init(config Config) {
	if err := Global.Apply(config); err != nil {
		panic(err)
	}
}

// Reset 调用 Global.Apply(Config{}) 重置配置信息。
func Reset() {
	Global.Apply(Config{})
}

// LoggerLevel 返回对应 loggerName 的日志等级。
func LoggerLevel(loggerName string) string {
	return Global.Level(loggerName).String()
}

// ActivateSpec 接收的字符串 spec 的格式是：logger1,logger2=level:logger3=level:level。没有指定 logger 的 level 会被作为默认日志等级。
func ActivateSpec(spec string) {
	if err := Global.ActivateSpec(spec); err != nil {
		panic(err)
	}
}

func DefaultLevel() string {
	return defaultLevel.String()
}

func SetWriter(w io.Writer) io.Writer {
	return Global.SetWriter(w)
}

func SetObserver(o Observer) Observer {
	return Global.SetObserver(o)
}

func MustGetLogger(loggerName string) *HyperchainLogger {
	return Global.Logger(loggerName)
}
