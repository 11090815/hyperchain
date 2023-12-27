package metrics

/*

	1. Counter（计数器）：
		· Counter是一个递增的整数，可以用于统计事件发生的次数或数量。
		· 特点：只能递增，不会减少；可以重置为初始值。
		· 适用场景：用于记录请求次数、错误次数、任务完成次数等。

	2. Gauge（仪表盘）：
		· Gauge是可以任意增减的数值，用于表示某个瞬时值或实时状态。
		· 特点：可以增加或减少；没有上限或下限。
		· 适用场景：用于记录当前连接数、内存使用量、CPU利用率等实时变化的指标。

	3. Histogram（直方图）：
		· Histogram是用于统计和分析数据分布的指标，通常用于测量数据的分布情况和各个区间的频率。
		· 特点：可以统计数据的分布情况，包括最大值、最小值、平均值、中位数等。
		· 适用场景：用于统计请求响应时间、请求大小、数据库查询结果数量等。

*/

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
