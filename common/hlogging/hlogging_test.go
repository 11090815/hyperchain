package hlogging_test

import (
	"os"
	"testing"

	"github.com/11090815/hyperchain/common/hlogging"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"
)

func TestNewLogging(t *testing.T) {
	logging, err := hlogging.NewLogging(hlogging.Config{})
	require.Nil(t, err)
	require.Equal(t, zapcore.InfoLevel, logging.DefaultLevel())

	_, err = hlogging.NewLogging(hlogging.Config{LogSpec: "::=broken=::"})
	require.Error(t, err)
}

func TestNewLoggingWithEnvironment(t *testing.T) {
	t.Setenv("HYPERCHAIN_LOGGING_SPEC", "warn")
	logging, err := hlogging.NewLogging(hlogging.Config{})
	require.Nil(t, err)
	require.Equal(t, zapcore.WarnLevel, logging.DefaultLevel())

	os.Unsetenv("HYPERCHAIN_LOGGING_SPEC")
	logging, err = hlogging.NewLogging(hlogging.Config{})
	require.Nil(t, err)
	require.Equal(t, zapcore.InfoLevel, logging.DefaultLevel())
}

func TestLoggingSetWriter(t *testing.T) {
	logging, err := hlogging.NewLogging(hlogging.Config{
		Writer: os.Stdout,
	})
	require.NoError(t, err)

	logging.Write([]byte("hello world"))
	logging.Sync()
}

func TestNamedLogger(t *testing.T) {
	w := os.Stdout
	hlogging.Reset()
	hlogging.SetWriter(w)
	hlogging.ActivateSpec("blockchain=info:blockchain.peer=error:p2p=warn")

	logger := hlogging.MustGetLogger("blockchain")
	logger.Debug("debug from blockchain")

	logger = hlogging.MustGetLogger("p2p")
	logger.Debug("debug from p2p")

	logger = hlogging.MustGetLogger("p2p").Named("blockchain.peer")
	logger.Info("info from blockchain.peer")
}
