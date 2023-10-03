package enc_test

import (
	"fmt"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/11090815/hyperchain/common/hlogging/enc"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"
)

func TestParseFormat(t *testing.T) {
	spec := "%{color:bold} [%{module}] %{color:reset}%{time} %{longfunc} %{color}%{level}%{color:reset} %{id} -> %{message}"

	formatters, err := enc.ParseFormat(spec)
	require.NoError(t, err)

	entry := zapcore.Entry{
		Level:      zapcore.DebugLevel,
		Time:       time.Now(),
		LoggerName: "test-logger",
		Message:    "test log formatter",
	}

	for _, f := range formatters {
		f.Format(os.Stdout, entry, nil)
	}
}

func TestRegexp(t *testing.T) {
	var formatRegexp = regexp.MustCompile(`%{(color|id|level|message|module|shortfunc|longfunc|time)(?::(.*?))?}`)

	spec := "%{color:bold} [%{module}] %{color:reset}"

	matches := formatRegexp.FindAllStringSubmatchIndex(spec, -1)

	fmt.Println(matches)
}
