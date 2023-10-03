package enc_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	zaplogfmt "github.com/sykesm/zap-logfmt"
	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"
)

func TestTimeFormat(t *testing.T) {
	fmt.Println(time.Now().Format("2006-01-02T15:04:05"))
	time.Sleep(time.Second)
	fmt.Println(time.Now().Format("2006-01-02T15:04:05"))
}

func TestHowToUseZapcoreEncoder(t *testing.T) {
	// 1. 实例化一个 zapcore.Encoder
	encoder := zaplogfmt.NewEncoder(zapcore.EncoderConfig{
		LineEnding: "\n",
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeTime: func(t time.Time, pae zapcore.PrimitiveArrayEncoder) {
			pae.AppendString(t.Format("2006-01-02T15:04:05"))
		},
	})

	// 2. 实例化一个 zapcore.Entry
	entry := zapcore.Entry{
		Level: zapcore.InfoLevel,
		Time: time.Now(),
		LoggerName: "test-logger",
		Message: "output a test message",
	}

	// 3. 实例化若干个 zapcore.Field
	fields := []zapcore.Field{
		{Key: "field1-key", Type: zapcore.StringType, Integer: 1, String: "field1-string", Interface: nil},
		{Key: "field2-key", Type: zapcore.StringType, Integer: 1, String: "field2-string", Interface: nil},
	}

	// 3. 实例化一个 buffer.Pool
	pool := buffer.NewPool()

	// 4. 从 pool 里拿出一个 buffer.Buffer
	line := pool.Get()

	// 5. 编码 entry 和 fields
	encodedFields, err := encoder.EncodeEntry(entry, fields)
	require.NoError(t, err)

	// 6. 将编码后的 entry 和 fields 以字符串的形式推送到 buffer.Buffer 里
	line.AppendString(encodedFields.String())
	encodedFields.Free()

	// 7. 打印输出
	fmt.Println(line.String())
}