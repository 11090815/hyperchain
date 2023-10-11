package metrics

type Provider interface {
	NewCounter(CounterOpts) Counter
	NewGauge(GaugeOpts) Gauge
	NewHistogram(HistogramOpts) Histogram
}

type Counter interface {
	// 调用 With 方法后，statsd.Counter 会被重新实例化，原来的 Namer 和 Statsd 就都没了。
	// type Counter struct {
	//	Counter        *statsd.Counter
	//	namer          *internal.Namer
	//	statsdProvider *statsd.Statsd
	// }
	// func (c *Counter) With(labelValues ...string) metrics.Counter {
	//	name := c.namer.Format(labelValues...)
	//	return &Counter{Counter: c.statsdProvider.NewCounter(name, 1)}
	// }
	With(labelValues ...string) Counter
	Add(delta float64)
}

type CounterOpts struct {
	Namespace    string
	Subsystem    string
	Name         string
	Help         string
	LabelNames   []string
	LabelHelp    map[string]string
	StatsdFormat string
}

// Gauge 量表
type Gauge interface {
	// 调用 With 方法后，statsd.Gauge 会被重新实例化，原来的 Namer 和 Statsd 就都没了。
	// type Gauge struct {
	// 	Gauge          *statsd.Gauge
	// 	namer          *internal.Namer
	//	statsdProvider *statsd.Statsd
	// }
	// func (g *Gauge) With(labelValues ...string) metrics.Gauge {
	//	name := g.namer.Format(labelValues...)
	//	return &Gauge{Gauge: g.statsdProvider.NewGauge(name)}
	// }
	With(labelValues ...string) Gauge
	Add(delta float64)
	Set(value float64)
}

type GaugeOpts struct {
	Namespace    string
	Subsystem    string
	Name         string
	Help         string
	LabelNames   []string
	LabelHelp    map[string]string
	StatsdFormat string
}

// Histogram 柱状图
type Histogram interface {
	// 调用 With 方法后，statsd.Timing 会被重新实例化，原来的 Namer 和 Statsd 就都没了。
	// type Histogram struct {
	// 	Timing         *statsd.Timing
	// 	namer          *internal.Namer
	// 	statsdProvider *statsd.Statsd
	// }
	// func (h *Histogram) With(labelValues ...string) metrics.Histogram {
	// 	name := h.namer.Format(labelValues...)
	//	return &Histogram{Timing: h.statsdProvider.NewTiming(name, 1)}
	// }
	With(labelValues ...string) Histogram
	Observe(value float64)
}

type HistogramOpts struct {
	Namespace    string
	Subsystem    string
	Name         string
	Help         string
	Buckets      []float64
	LabelNames   []string
	LabelHelp    map[string]string
	StatsdFormat string // statsd：统计
}
