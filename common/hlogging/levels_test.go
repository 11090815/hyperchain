package hlogging_test

import (
	"testing"

	"github.com/11090815/hyperchain/common/hlogging"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"
)

func TestLoggerLevelsActivateSpec(t *testing.T) {
	tests := []struct {
		spec                 string
		expectedLevels       map[string]zapcore.Level
		expectedDefaultLevel zapcore.Level
	}{
		{
			spec:                 "debug",
			expectedLevels:       map[string]zapcore.Level{},
			expectedDefaultLevel: zapcore.DebugLevel,
		},
		{
			spec:                 "INFO",
			expectedLevels:       map[string]zapcore.Level{},
			expectedDefaultLevel: zapcore.InfoLevel,
		},
		{
			spec: "logger=info:debug",
			expectedLevels: map[string]zapcore.Level{
				"logger":   zapcore.InfoLevel,
				"logger.a": zapcore.InfoLevel,
			},
			expectedDefaultLevel: zapcore.DebugLevel,
		},
		{
			spec: "a.b=info:a,z=error:a.b.c.d,e.f.g=debug:error",
			expectedLevels: map[string]zapcore.Level{
				"a":       zapcore.ErrorLevel,
				"a.b":     zapcore.InfoLevel,
				"a.b.c":   zapcore.InfoLevel,
				"e":       zapcore.ErrorLevel,
				"a.b.c.d": zapcore.DebugLevel,
				"e.f.g":   zapcore.DebugLevel,
				"e.f":     zapcore.ErrorLevel,
				"z":       zapcore.ErrorLevel,
				"z.f":     zapcore.ErrorLevel,
			},
			expectedDefaultLevel: zapcore.ErrorLevel,
		},
	}

	for _, test := range tests {
		ll := &hlogging.LoggerLevels{}

		err := ll.ActivateSpec(test.spec)
		require.NoError(t, err)
		require.Equal(t, ll.DefaultLevel(), test.expectedDefaultLevel)
		for name, lvl := range test.expectedLevels {
			t.Run(name, func(t *testing.T) {
				require.Equal(t, lvl, ll.Level(name))
			})
		}
	}
}
