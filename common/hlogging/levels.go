package hlogging

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"sync"

	"go.uber.org/zap/zapcore"
)

const DisabledLevel = zapcore.Level(math.MinInt8)

var loggerNameRegexp = regexp.MustCompile(`^[[:alnum:]_#:-]+(\.[[:alnum:]_#:-]+)*$`)

type LoggerLevels struct {
	mutex        *sync.RWMutex
	levelCache   map[string]zapcore.Level // loggerName => zapcore.Level，loggerName 的格式应当是 xxx.xxx.xxx
	specs        map[string]zapcore.Level
	defaultLevel zapcore.Level
	minLevel     zapcore.Level
}

func (ll *LoggerLevels) DefaultLevel() zapcore.Level {
	ll.mutex.RLock()
	defer ll.mutex.RUnlock()
	return ll.defaultLevel
}

// ActivateSpec 接收的字符串 spec 的格式是：logger1,logger2=level:logger3=level:level。没有指定 logger 的 level 会被作为默认日志等级。
func (ll *LoggerLevels) ActivateSpec(spec string) error {
	ll.mutex.Lock()
	defer ll.mutex.Unlock()

	defaultLevel := zapcore.InfoLevel
	specs := make(map[string]zapcore.Level)

	for _, field := range strings.Split(spec, ":") {
		split := strings.Split(field, "=")
		switch len(split) { // 按等号 "=" 分割
		case 1: // field => level
			if field != "" && !IsValidLevel(field) {
				return fmt.Errorf("invalid logging specification '%s': bad segment '%s'", spec, field)
			}
			defaultLevel = NameToLevel(field)
		case 2: // field => logger1,logger2=level
			if split[0] == "" {
				return fmt.Errorf("invalid logging specification '%s': no logger specified in segment '%s'", spec, field)
			}
			if field != "" && !IsValidLevel(split[1]) {
				return fmt.Errorf("invalid logging specification '%s': bad segment '%s'", spec, field)
			}
			level := NameToLevel(split[1])
			loggers := strings.Split(split[0], ",")
			for _, logger := range loggers {
				if !isValidLoggerName(strings.TrimSuffix(logger, ".")) {
					return fmt.Errorf("invalid logging specification '%s': bad logger name '%s'", spec, logger)
				}
				specs[logger] = level
			}
		default:
			return fmt.Errorf("invalid logging specification '%s': bad segment '%s'", spec, field)
		}
	}

	minLevel := defaultLevel
	for _, lvl := range specs {
		if lvl < minLevel {
			minLevel = lvl
		}
	}

	ll.minLevel = minLevel
	ll.defaultLevel = defaultLevel
	ll.specs = specs
	ll.levelCache = make(map[string]zapcore.Level)
	return nil
}

// Level 返回与给定的 loggerName 绑定的日志等级，首先从缓冲区中寻找有没有存储 loggerName:level，如果没有，那么再递归地从 specs 中寻找，例如给定的 loggerName 是 aaa.bbb.ccc，在 specs 中存储了 aaa.bbb:InfoLevel，那么返回的日志记录等级就是 InfoLevel。
func (ll *LoggerLevels) Level(loggerName string) zapcore.Level {
	if lvl, ok := ll.cachedLevel(loggerName); ok {
		return lvl
	}

	ll.mutex.Lock()
	defer ll.mutex.Unlock()
	level := ll.calculateLevel(loggerName)
	ll.levelCache[loggerName] = level
	return level
}

func (ll *LoggerLevels) calculateLevel(loggerName string) zapcore.Level {
	candidate := loggerName + "."
	for {
		if lvl, ok := ll.specs[candidate]; ok {
			return lvl
		}

		idx := strings.LastIndex(candidate, ".")
		if idx < 0 {
			return ll.defaultLevel
		}
		candidate = candidate[:idx]
	}
}

// cachedLevel 根据给定的 loggerName，返回存储在缓冲区 levelCache 中与 loggerName 对应设置的日志等级 zapcore.Level。
func (ll *LoggerLevels) cachedLevel(loggerName string) (lvl zapcore.Level, ok bool) {
	ll.mutex.RLock()
	defer ll.mutex.RUnlock()
	lvl, ok = ll.levelCache[loggerName]
	return
}

func (ll *LoggerLevels) Spec() string {
	ll.mutex.RLock()
	defer ll.mutex.RUnlock()

	var fields []string
	for k, v := range ll.specs {
		fields = append(fields, fmt.Sprintf("%s=%s", k, v))
	}
	sort.Strings(fields) // 升序排列
	fields = append(fields, ll.defaultLevel.String())

	return strings.Join(fields, ":")
}

// Enabled 判断给定的日志等级 level 是否高于或等于 LoggerLevels 的 minLevel。
func (ll *LoggerLevels) Enabled(lvl zapcore.Level) bool {
	ll.mutex.RLock()
	defer ll.mutex.RUnlock()
	return ll.minLevel.Enabled(lvl)
}

/*** 🐋 ***/

// NameToLevel 如果给定的字符串 level 所指示的日志等级是未知的，则返回 InfoLevel，否则返回与 level 对应的 zapcore.Level。
func NameToLevel(level string) zapcore.Level {
	l, err := nameToLevel(level)
	if err != nil {
		return zapcore.InfoLevel
	}
	return l
}

func nameToLevel(level string) (zapcore.Level, error) {
	switch level {
	case "debug", "DEBUG":
		return zapcore.DebugLevel, nil
	case "info", "INFO":
		return zapcore.InfoLevel, nil
	case "warn", "WARN":
		return zapcore.WarnLevel, nil
	case "error", "ERROR":
		return zapcore.ErrorLevel, nil
	case "panic", "PANIC":
		return zapcore.PanicLevel, nil
	default:
		return DisabledLevel, fmt.Errorf("unknown log level: %s", level)
	}
}

func IsValidLevel(level string) bool {
	_, err := nameToLevel(level)
	return err == nil
}

/*** 🐋 ***/

func isValidLoggerName(loggerName string) bool {
	return loggerNameRegexp.MatchString(loggerName)
}
