package enc

import (
	"fmt"
	"io"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"go.uber.org/zap/zapcore"
)

// "[%{module}] %{shortfunc} -> %{level:.4s} %{id:04x} %{message}"
var formatRegexp = regexp.MustCompile(`%{(color|id|level|message|module|shortfunc|longfunc|time)(?::(.*?))?}`)

func ParseFormat(spec string) ([]Formatter, error) {
	cursor := 0
	formatters := []Formatter{}

	matches := formatRegexp.FindAllStringSubmatchIndex(spec, -1)
	for _, m := range matches {
		start, end := m[0], m[1]
		verbStart, verbEnd := m[2], m[3]
		formatStart, formatEnd := m[4], m[5]

		if start > cursor {
			formatters = append(formatters, newStringFormatter(spec[cursor:start]))
		}

		var format string
		if formatStart >= 0 {
			format = spec[formatStart:formatEnd]
		}

		formatter, err := NewFormatter(spec[verbStart:verbEnd], format)
		if err != nil {
			return nil, err
		}

		formatters = append(formatters, formatter)
		cursor = end
	}

	if cursor != len(spec) {
		formatters = append(formatters, newStringFormatter(spec[cursor:]))
	}

	return formatters, nil
}

func NewFormatter(verb, option string) (Formatter, error) {
	switch verb {
	case "color":
		return newColorFormatter(option)
	case "id":
		return newSequenceFormatter(option), nil
	case "level":
		return newLevelFormatter(option), nil
	case "message":
		return newMessageFormatter(option), nil
	case "module":
		return newModuleFormatter(option), nil
	case "shortfunc":
		return newFuncFormatter(option, "shortfunc"), nil
	case "longfunc":
		return newFuncFormatter(option, "longfunc"), nil
	case "time":
		return newTimeFormatter(option), nil
	default:
		return nil, fmt.Errorf("unknown verb: %s, should be one of [color | id | level | message | module | shortfunc | longfunc | time]", verb)
	}
}

/*** 🐋 ***/

type MultiFormatter struct {
	mutex      sync.RWMutex
	formatters []Formatter
}

func NewMultiFormatter(formatters ...Formatter) *MultiFormatter {
	return &MultiFormatter{
		formatters: formatters,
	}
}

func (mf *MultiFormatter) Format(w io.Writer, entry zapcore.Entry, fields []zapcore.Field) {
	mf.mutex.RLock()
	for _, f := range mf.formatters {
		f.Format(w, entry, fields)
	}
	mf.mutex.RUnlock()
}

func (mf *MultiFormatter) SetFormatters(formatters []Formatter) {
	mf.mutex.Lock()
	mf.formatters = formatters
	mf.mutex.Unlock()
}

/*** 🐋 ***/

type stringFormatter struct {
	value string
}

func newStringFormatter(value string) stringFormatter {
	return stringFormatter{
		value: value,
	}
}

func (sf stringFormatter) Format(w io.Writer, entry zapcore.Entry, fields []zapcore.Field) {
	fmt.Fprintf(w, "%s", sf.value)
}

/*** 🐋 ***/

type colorFormatter struct {
	bold  bool
	reset bool
}

func newColorFormatter(option string) (colorFormatter, error) {
	switch option {
	case "bold":
		return colorFormatter{bold: true}, nil
	case "reset":
		return colorFormatter{reset: true}, nil
	case "":
		return colorFormatter{}, nil
	default:
		return colorFormatter{}, fmt.Errorf("invalid color option: %s, should be one of [bold | reset]", option)
	}
}

func (cf colorFormatter) LevelColor(l zapcore.Level) Color {
	switch l {
	case zapcore.DebugLevel:
		return ColorCyan
	case zapcore.InfoLevel:
		return ColorBlue
	case zapcore.WarnLevel:
		return ColorYellow
	case zapcore.ErrorLevel:
		return ColorRed
	case zapcore.PanicLevel, zapcore.DPanicLevel, zapcore.FatalLevel:
		return ColorMagenta
	default:
		return ColorNone
	}
}

func (cf colorFormatter) Format(w io.Writer, entry zapcore.Entry, fields []zapcore.Field) {
	switch {
	case cf.reset:
		fmt.Fprint(w, ResetColor())
	case cf.bold:
		fmt.Fprint(w, cf.LevelColor(entry.Level).Bold())
	default:
		fmt.Fprint(w, cf.LevelColor(entry.Level).Normal())
	}
}

/*** 🐋 ***/

type levelFormatter struct {
	formatVerb string
}

func newLevelFormatter(fv string) levelFormatter {
	return levelFormatter{
		formatVerb: "%" + stringOrDefault(fv, "s"),
	}
}

func (lf levelFormatter) Format(w io.Writer, entry zapcore.Entry, fields []zapcore.Field) {
	fmt.Fprintf(w, lf.formatVerb, entry.Level.CapitalString())
}

/*** 🐋 ***/

type messageFormatter struct {
	formatVerb string
}

func newMessageFormatter(fv string) messageFormatter {
	return messageFormatter{
		formatVerb: "%" + stringOrDefault(fv, "s"),
	}
}

func (mf messageFormatter) Format(w io.Writer, entry zapcore.Entry, fields []zapcore.Field) {
	fmt.Fprintf(w, mf.formatVerb, strings.TrimRight(entry.Message, "\n"))
}

/*** 🐋 ***/

type moduleFormatter struct {
	formatVerb string
}

func newModuleFormatter(fv string) moduleFormatter {
	return moduleFormatter{
		formatVerb: "%" + stringOrDefault(fv, "s"),
	}
}

func (mf moduleFormatter) Format(w io.Writer, entry zapcore.Entry, fields []zapcore.Field) {
	fmt.Fprintf(w, mf.formatVerb, entry.LoggerName)
}

/*** 🐋 ***/

var sequence uint64 = 0

type sequenceFormatter struct {
	formatVerb string
}

func newSequenceFormatter(fv string) sequenceFormatter {
	return sequenceFormatter{
		formatVerb: "%" + stringOrDefault(fv, "d"),
	}
}

func (sf sequenceFormatter) Format(w io.Writer, entry zapcore.Entry, fields []zapcore.Field) {
	fmt.Fprintf(w, sf.formatVerb, atomic.AddUint64(&sequence, 1))
}

/*** 🐋 ***/

type funcFormatter struct {
	formatVerb string
	kind       string // shortFunc | longFunc
}

func newFuncFormatter(fv string, kind string) funcFormatter {
	return funcFormatter{
		formatVerb: "%" + stringOrDefault(fv, "s"),
		kind:       kind,
	}
}

func (ff funcFormatter) Format(w io.Writer, entry zapcore.Entry, fields []zapcore.Field) {
	// 利用给定的程序计数器地址返回 runtime.Func
	f := runtime.FuncForPC(entry.Caller.PC)
	if f == nil {
		fmt.Fprintf(w, ff.formatVerb, "(unknown)")
		return
	}

	fname := f.Name()
	if ff.kind == "longfunc" {
		fmt.Fprintf(w, ff.formatVerb, fname)
		return
	}
	funcIdx := strings.LastIndex(fname, ".")
	fmt.Fprintf(w, ff.formatVerb, fname[funcIdx+1:])
}

/*** 🐋 ***/

type timeFormatter struct {
	layout string
}

func newTimeFormatter(layout string) timeFormatter {
	return timeFormatter{
		layout: stringOrDefault(layout, "2006-01-02T15:04:05"),
	}
}

func (tf timeFormatter) Format(w io.Writer, entry zapcore.Entry, fields []zapcore.Field) {
	fmt.Fprint(w, entry.Time.Format(tf.layout))
}

func stringOrDefault(str, dflt string) string {
	if str != "" {
		return str
	}
	return dflt
}
