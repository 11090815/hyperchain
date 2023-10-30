package hlogging

import "go.uber.org/zap/zapcore"

type Encoding int8

const (
	CONSOLE = iota
	JSON
	LOGFMT
)

type EncodingSelector interface {
	Encoding() Encoding
}

type core struct {
	zapcore.LevelEnabler
	Levels   *LoggerLevels
	Encoders map[Encoding]zapcore.Encoder
	Selector EncodingSelector
	Output   zapcore.WriteSyncer
	Observer Observer
}

func (c *core) With(fields []zapcore.Field) zapcore.Core {
	clones := make(map[Encoding]zapcore.Encoder)

	for name, enc := range c.Encoders {
		clone := enc.Clone()
		addFields(clone, fields)
		clones[name] = clone
	}

	return &core{
		LevelEnabler: c.LevelEnabler,
		Levels:       c.Levels,
		Encoders:     clones,
		Selector:     c.Selector,
		Output:       c.Output,
		Observer:     c.Observer,
	}
}

func (c *core) Check(e zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Observer != nil {
		c.Observer.Check(e, ce)
	}

	if c.Enabled(e.Level) && c.Levels.Level(e.LoggerName).Enabled(e.Level) {
		return ce.AddCore(e, c) // AddCore 添加一个已同意记录此 CheckedEntry 的 Core。它的目的是供 Core.Check 实现使用，并可安全地调用为空 CheckedEntry 引用。
	}
	return ce
}

func (c *core) Write(e zapcore.Entry, fields []zapcore.Field) error {
	encoding := c.Selector.Encoding()
	enc := c.Encoders[encoding]

	// EncodeEntry 将条目和字段以及累积的上下文编码成字节缓冲区并返回。任何空字段（包括 "条目 "类型的字段）都应省略。
	buf, err := enc.EncodeEntry(e, fields)
	if err != nil {
		return err
	}

	_, err = c.Output.Write(buf.Bytes())
	buf.Free()
	if err != nil {
		return err
	}

	if e.Level >= zapcore.PanicLevel {
		c.Sync()
	}

	if c.Observer != nil {
		c.Observer.WriteEntry(e, fields)
	}

	return nil
}

func (c *core) Sync() error {
	return c.Output.Sync()
}

type Observer interface {
	Check(e zapcore.Entry, ce *zapcore.CheckedEntry)
	WriteEntry(e zapcore.Entry, fields []zapcore.Field)
}

func addFields(enc zapcore.ObjectEncoder, fields []zapcore.Field) {
	for i := range fields {
		fields[i].AddTo(enc) // AddTo 通过 ObjectEncoder 接口导出一个字段。它主要对库作者有用，在大多数应用程序中都不需要。
	}
}
