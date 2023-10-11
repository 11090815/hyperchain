package statsd

import (
	"github.com/11090815/hyperchain/common/metrics"
	"github.com/11090815/hyperchain/common/metrics/internal"
	"github.com/go-kit/kit/metrics/statsd"
)

const defaultFormat = "%{#fqname}"

type Provider struct {
	Statsd *statsd.Statsd
}

func (p *Provider) NewCounter(opts metrics.CounterOpts) metrics.Counter {
	if opts.StatsdFormat == "" {
		opts.StatsdFormat = defaultFormat
	}
	counter := &Counter{
		statsdProvider: p.Statsd,
		namer:          internal.NewCounterNamer(opts),
	}
	if len(opts.LabelNames) == 0 {
		counter.Counter = p.Statsd.NewCounter(counter.namer.Format(), 1.0)
	}

	return counter
}

func (p *Provider) NewGauge(opts metrics.GaugeOpts) metrics.Gauge {
	if opts.StatsdFormat == "" {
		opts.StatsdFormat = defaultFormat
	}
	gauge := &Gauge{
		statsdProvider: p.Statsd,
		namer:          internal.NewGaugeNamer(opts),
	}
	if len(opts.LabelNames) == 0 {
		gauge.Gauge = p.Statsd.NewGauge(gauge.namer.Format())
	}

	return gauge
}

func (p *Provider) NewHistogram(opts metrics.HistogramOpts) metrics.Histogram {
	if opts.StatsdFormat == "" {
		opts.StatsdFormat = defaultFormat
	}
	histogram := &Histogram{
		statsdProvider: p.Statsd,
		namer:          internal.NewHistogramNamer(opts),
	}
	if len(opts.LabelNames) == 0 {
		histogram.Timing = p.Statsd.NewTiming(histogram.namer.Format(), 1.0)
	}

	return histogram
}

type Counter struct {
	Counter        *statsd.Counter
	namer          *internal.Namer
	statsdProvider *statsd.Statsd
}

func (c *Counter) With(labelValues ...string) metrics.Counter {
	name := c.namer.Format(labelValues...)
	return &Counter{Counter: c.statsdProvider.NewCounter(name, 1)}
}

func (c *Counter) Add(delta float64) {
	if c.Counter == nil {
		panic("You should call the With() method first to instantiate the Counter")
	}
	c.Counter.Add(delta)
}

type Gauge struct {
	Gauge          *statsd.Gauge
	namer          *internal.Namer
	statsdProvider *statsd.Statsd
}

func (g *Gauge) With(labelValues ...string) metrics.Gauge {
	name := g.namer.Format(labelValues...)
	return &Gauge{Gauge: g.statsdProvider.NewGauge(name)}
}

func (g *Gauge) Add(delta float64) {
	if g.Gauge == nil {
		panic("You should call the With() method first to instantiate the Gauge")
	}
	g.Gauge.Add(delta)
}

func (g *Gauge) Set(value float64) {
	if g.Gauge == nil {
		panic("You should call the With() method first to instantiate the Gauge")
	}
	g.Gauge.Set(value)
}

type Histogram struct {
	Timing         *statsd.Timing
	namer          *internal.Namer
	statsdProvider *statsd.Statsd
}

func (h *Histogram) With(labelValues ...string) metrics.Histogram {
	name := h.namer.Format(labelValues...)
	return &Histogram{Timing: h.statsdProvider.NewTiming(name, 1)}
}

func (h *Histogram) Observe(value float64) {
	if h.Timing == nil {
		panic("You should call the With() method first to instantiate the Histogram")
	}
	h.Timing.Observe(value)
}
