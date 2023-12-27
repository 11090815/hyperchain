package prometheus_test

import (
	"fmt"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/11090815/hyperchain/common/metrics"
	"github.com/11090815/hyperchain/common/metrics/prometheus"
	goprometheus "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stretchr/testify/assert"
)

func TestMetricsCounter(t *testing.T) {
	registry := goprometheus.NewRegistry()
	goprometheus.DefaultRegisterer = registry
	goprometheus.DefaultGatherer = registry

	server := httptest.NewServer(promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	client := server.Client()

	counterOpts := metrics.CounterOpts{
		Namespace:  "www",
		Subsystem:  "metrics",
		Name:       "counter",
		Help:       "This is some help text for the counter",
		LabelNames: []string{"alpha", "beta"},
	}

	provider := &prometheus.Provider{}
	counter := provider.NewCounter(counterOpts)
	counter.With("alpha", "a", "beta", "b").Add(1)
	// counter.With("alpha", "a", "beta", "b", "lambda", "l").Add(1) panic: inconsistent label cardinality: expected 2 label values but got 3 in prometheus.Labels{"alpha":"a", "beta":"b", "lambda":"l"}
	// counter.Add(2) panic: inconsistent label cardinality: expected 2 label values but got 0 in prometheus.Labels{}
	// counter.With("alpha", "a").Add(1) panic: inconsistent label cardinality: expected 2 label values but got 1 in prometheus.Labels{"alpha":"a"}
	// counter.With("alpha", "aardvark", "lambda", "l").Add(2) panic: label name "beta" missing in label map

	resp, err := client.Get(fmt.Sprintf("http://%s/metrics", server.Listener.Addr().String()))
	assert.Equal(t, err, nil)

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	assert.Equal(t, err, nil)

	fmt.Println(string(body))
}
