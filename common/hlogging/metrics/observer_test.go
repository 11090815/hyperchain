package metrics_test

import (
	"fmt"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/11090815/hyperchain/common/hlogging/metrics"
	"github.com/11090815/hyperchain/common/metrics/prometheus"
	goprometheus "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zapcore"
)

func TestObserver(t *testing.T) {
	registry := goprometheus.NewRegistry()
	goprometheus.DefaultRegisterer = registry
	goprometheus.DefaultGatherer = registry

	server := httptest.NewServer(promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	client := server.Client()

	provider := &prometheus.Provider{}

	checkedCounter := provider.NewCounter(metrics.CheckedCountOpts)
	writtenCounter := provider.NewCounter(metrics.WriteCountOpts)

	observer := &metrics.Observer{
		CheckedCounter: checkedCounter,
		WrittenCounter: writtenCounter,
	}

	observer.Check(zapcore.Entry{Level: zapcore.DebugLevel}, nil)
	observer.WriteEntry(zapcore.Entry{Level: zapcore.InfoLevel}, nil)

	resp, err := client.Get(fmt.Sprintf("http://%s/metrics", server.Listener.Addr().String()))
	assert.Equal(t, err, nil)

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	assert.Equal(t, err, nil)

	fmt.Println(string(body))
}
