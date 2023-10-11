package statsd_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/11090815/hyperchain/common/metrics"
	"github.com/11090815/hyperchain/common/metrics/statsd"
	kitstatsd "github.com/go-kit/kit/metrics/statsd"
)

func TestStatsdHistogram(t *testing.T) {
	var s *kitstatsd.Statsd = kitstatsd.New("", nil)
	provider := &statsd.Provider{Statsd: s}

	var histogramOpts metrics.HistogramOpts = metrics.HistogramOpts{
		Namespace: "www",
		Subsystem: "metrics",
		Name: "histogram",
		StatsdFormat: "%{#namespace}.%{#subsystem}.%{#name}-%{alpha}.%{beta}",
		LabelNames: []string{"alpha", "beta"},
	}

	histogram := provider.NewHistogram(histogramOpts)
	for i := 1; i <= 5; i++ {
		for _, alpha := range []string{"x", "y", "z"} {
			// histogram.With("alpha", alpha).Observe(float64(i)) panic: invalid label in name format: beta
			histogram.With("alpha", alpha, "beta", "b").Observe(float64(i))
			buf := &bytes.Buffer{}
			s.WriteTo(buf)
			fmt.Println(buf.String())
		}
	}

	histogramOpts.LabelNames = nil
	histogramOpts.StatsdFormat = ""

	histogram = provider.NewHistogram(histogramOpts)
	histogram.Observe(1)
	buf := &bytes.Buffer{}
	s.WriteTo(buf)
	fmt.Println(buf.String())

	histogramOpts.StatsdFormat = "%{#namespace}.%{#subsystem}.%{#name}"
	histogram = provider.NewHistogram(histogramOpts)
	for i := 0; i < 10; i++ {
		histogram.Observe(float64(i))
		buf := &bytes.Buffer{}
		s.WriteTo(buf)
		fmt.Println(buf.String())
	}
}
