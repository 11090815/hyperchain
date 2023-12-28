package metricsfakes

import (
	"sync"

	"github.com/11090815/hyperchain/common/metrics"
)

type Counter struct {
	AddStub        func(float64)
	addMutex       sync.RWMutex
	addArgsForCall []struct {
		arg1 float64
	}
	WithStub        func(...string) metrics.Counter
	withMutex       sync.RWMutex
	withArgsForCall []struct {
		arg1 []string
	}
	withReturns struct {
		result1 metrics.Counter
	}
	withReturnsOnCall map[int]struct {
		result1 metrics.Counter
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *Counter) Add(arg1 float64) {
	fake.addMutex.Lock()
	fake.addArgsForCall = append(fake.addArgsForCall, struct {
		arg1 float64
	}{arg1})
	fake.recordInvocation("Add", []interface{}{arg1})
	fake.addMutex.Unlock()
	if fake.AddStub != nil {
		fake.AddStub(arg1)
	}
}

func (fake *Counter) AddCallCount() int {
	fake.addMutex.RLock()
	defer fake.addMutex.RUnlock()
	return len(fake.addArgsForCall)
}

func (fake *Counter) AddCalls(stub func(float64)) {
	fake.addMutex.Lock()
	defer fake.addMutex.Unlock()
	fake.AddStub = stub
}

func (fake *Counter) AddArgsForCall(i int) float64 {
	fake.addMutex.RLock()
	defer fake.addMutex.RUnlock()
	argsForCall := fake.addArgsForCall[i]
	return argsForCall.arg1
}

func (fake *Counter) With(arg1 ...string) metrics.Counter {
	fake.withMutex.Lock()
	ret, specificReturn := fake.withReturnsOnCall[len(fake.withArgsForCall)]
	fake.withArgsForCall = append(fake.withArgsForCall, struct {
		arg1 []string
	}{arg1})
	fake.recordInvocation("With", []interface{}{arg1})
	fake.withMutex.Unlock()
	if fake.WithStub != nil {
		return fake.WithStub(arg1...)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.withReturns
	return fakeReturns.result1
}

func (fake *Counter) WithCallCount() int {
	fake.withMutex.RLock()
	defer fake.withMutex.RUnlock()
	return len(fake.withArgsForCall)
}

func (fake *Counter) WithCalls(stub func(...string) metrics.Counter) {
	fake.withMutex.Lock()
	defer fake.withMutex.Unlock()
	fake.WithStub = stub
}

func (fake *Counter) WithArgsForCall(i int) []string {
	fake.withMutex.RLock()
	defer fake.withMutex.RUnlock()
	argsForCall := fake.withArgsForCall[i]
	return argsForCall.arg1
}

func (fake *Counter) WithReturns(result1 metrics.Counter) {
	fake.withMutex.Lock()
	defer fake.withMutex.Unlock()
	fake.WithStub = nil
	fake.withReturns = struct {
		result1 metrics.Counter
	}{result1}
}

func (fake *Counter) WithReturnsOnCall(i int, result1 metrics.Counter) {
	fake.withMutex.Lock()
	defer fake.withMutex.Unlock()
	fake.WithStub = nil
	if fake.withReturnsOnCall == nil {
		fake.withReturnsOnCall = make(map[int]struct {
			result1 metrics.Counter
		})
	}
	fake.withReturnsOnCall[i] = struct {
		result1 metrics.Counter
	}{result1}
}

func (fake *Counter) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.addMutex.RLock()
	defer fake.addMutex.RUnlock()
	fake.withMutex.RLock()
	defer fake.withMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *Counter) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}

var _ metrics.Counter = new(Counter)

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

type Gauge struct {
	AddStub        func(float64)
	addMutex       sync.RWMutex
	addArgsForCall []struct {
		arg1 float64
	}
	SetStub        func(float64)
	setMutex       sync.RWMutex
	setArgsForCall []struct {
		arg1 float64
	}
	WithStub        func(...string) metrics.Gauge
	withMutex       sync.RWMutex
	withArgsForCall []struct {
		arg1 []string
	}
	withReturns struct {
		result1 metrics.Gauge
	}
	withReturnsOnCall map[int]struct {
		result1 metrics.Gauge
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *Gauge) Add(arg1 float64) {
	fake.addMutex.Lock()
	fake.addArgsForCall = append(fake.addArgsForCall, struct {
		arg1 float64
	}{arg1})
	fake.recordInvocation("Add", []interface{}{arg1})
	fake.addMutex.Unlock()
	if fake.AddStub != nil {
		fake.AddStub(arg1)
	}
}

func (fake *Gauge) AddCallCount() int {
	fake.addMutex.RLock()
	defer fake.addMutex.RUnlock()
	return len(fake.addArgsForCall)
}

func (fake *Gauge) AddCalls(stub func(float64)) {
	fake.addMutex.Lock()
	defer fake.addMutex.Unlock()
	fake.AddStub = stub
}

func (fake *Gauge) AddArgsForCall(i int) float64 {
	fake.addMutex.RLock()
	defer fake.addMutex.RUnlock()
	argsForCall := fake.addArgsForCall[i]
	return argsForCall.arg1
}

func (fake *Gauge) Set(arg1 float64) {
	fake.setMutex.Lock()
	fake.setArgsForCall = append(fake.setArgsForCall, struct {
		arg1 float64
	}{arg1})
	fake.recordInvocation("Set", []interface{}{arg1})
	fake.setMutex.Unlock()
	if fake.SetStub != nil {
		fake.SetStub(arg1)
	}
}

func (fake *Gauge) SetCallCount() int {
	fake.setMutex.RLock()
	defer fake.setMutex.RUnlock()
	return len(fake.setArgsForCall)
}

func (fake *Gauge) SetCalls(stub func(float64)) {
	fake.setMutex.Lock()
	defer fake.setMutex.Unlock()
	fake.SetStub = stub
}

func (fake *Gauge) SetArgsForCall(i int) float64 {
	fake.setMutex.RLock()
	defer fake.setMutex.RUnlock()
	argsForCall := fake.setArgsForCall[i]
	return argsForCall.arg1
}

func (fake *Gauge) With(arg1 ...string) metrics.Gauge {
	fake.withMutex.Lock()
	ret, specificReturn := fake.withReturnsOnCall[len(fake.withArgsForCall)]
	fake.withArgsForCall = append(fake.withArgsForCall, struct {
		arg1 []string
	}{arg1})
	fake.recordInvocation("With", []interface{}{arg1})
	fake.withMutex.Unlock()
	if fake.WithStub != nil {
		return fake.WithStub(arg1...)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.withReturns
	return fakeReturns.result1
}

func (fake *Gauge) WithCallCount() int {
	fake.withMutex.RLock()
	defer fake.withMutex.RUnlock()
	return len(fake.withArgsForCall)
}

func (fake *Gauge) WithCalls(stub func(...string) metrics.Gauge) {
	fake.withMutex.Lock()
	defer fake.withMutex.Unlock()
	fake.WithStub = stub
}

func (fake *Gauge) WithArgsForCall(i int) []string {
	fake.withMutex.RLock()
	defer fake.withMutex.RUnlock()
	argsForCall := fake.withArgsForCall[i]
	return argsForCall.arg1
}

func (fake *Gauge) WithReturns(result1 metrics.Gauge) {
	fake.withMutex.Lock()
	defer fake.withMutex.Unlock()
	fake.WithStub = nil
	fake.withReturns = struct {
		result1 metrics.Gauge
	}{result1}
}

func (fake *Gauge) WithReturnsOnCall(i int, result1 metrics.Gauge) {
	fake.withMutex.Lock()
	defer fake.withMutex.Unlock()
	fake.WithStub = nil
	if fake.withReturnsOnCall == nil {
		fake.withReturnsOnCall = make(map[int]struct {
			result1 metrics.Gauge
		})
	}
	fake.withReturnsOnCall[i] = struct {
		result1 metrics.Gauge
	}{result1}
}

func (fake *Gauge) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.addMutex.RLock()
	defer fake.addMutex.RUnlock()
	fake.setMutex.RLock()
	defer fake.setMutex.RUnlock()
	fake.withMutex.RLock()
	defer fake.withMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *Gauge) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}

var _ metrics.Gauge = new(Gauge)

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

type Histogram struct {
	ObserveStub        func(float64)
	observeMutex       sync.RWMutex
	observeArgsForCall []struct {
		arg1 float64
	}
	WithStub        func(...string) metrics.Histogram
	withMutex       sync.RWMutex
	withArgsForCall []struct {
		arg1 []string
	}
	withReturns struct {
		result1 metrics.Histogram
	}
	withReturnsOnCall map[int]struct {
		result1 metrics.Histogram
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *Histogram) Observe(arg1 float64) {
	fake.observeMutex.Lock()
	fake.observeArgsForCall = append(fake.observeArgsForCall, struct {
		arg1 float64
	}{arg1})
	fake.recordInvocation("Observe", []interface{}{arg1})
	fake.observeMutex.Unlock()
	if fake.ObserveStub != nil {
		fake.ObserveStub(arg1)
	}
}

func (fake *Histogram) ObserveCallCount() int {
	fake.observeMutex.RLock()
	defer fake.observeMutex.RUnlock()
	return len(fake.observeArgsForCall)
}

func (fake *Histogram) ObserveCalls(stub func(float64)) {
	fake.observeMutex.Lock()
	defer fake.observeMutex.Unlock()
	fake.ObserveStub = stub
}

func (fake *Histogram) ObserveArgsForCall(i int) float64 {
	fake.observeMutex.RLock()
	defer fake.observeMutex.RUnlock()
	argsForCall := fake.observeArgsForCall[i]
	return argsForCall.arg1
}

func (fake *Histogram) With(arg1 ...string) metrics.Histogram {
	fake.withMutex.Lock()
	ret, specificReturn := fake.withReturnsOnCall[len(fake.withArgsForCall)]
	fake.withArgsForCall = append(fake.withArgsForCall, struct {
		arg1 []string
	}{arg1})
	fake.recordInvocation("With", []interface{}{arg1})
	fake.withMutex.Unlock()
	if fake.WithStub != nil {
		return fake.WithStub(arg1...)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.withReturns
	return fakeReturns.result1
}

func (fake *Histogram) WithCallCount() int {
	fake.withMutex.RLock()
	defer fake.withMutex.RUnlock()
	return len(fake.withArgsForCall)
}

func (fake *Histogram) WithCalls(stub func(...string) metrics.Histogram) {
	fake.withMutex.Lock()
	defer fake.withMutex.Unlock()
	fake.WithStub = stub
}

func (fake *Histogram) WithArgsForCall(i int) []string {
	fake.withMutex.RLock()
	defer fake.withMutex.RUnlock()
	argsForCall := fake.withArgsForCall[i]
	return argsForCall.arg1
}

func (fake *Histogram) WithReturns(result1 metrics.Histogram) {
	fake.withMutex.Lock()
	defer fake.withMutex.Unlock()
	fake.WithStub = nil
	fake.withReturns = struct {
		result1 metrics.Histogram
	}{result1}
}

func (fake *Histogram) WithReturnsOnCall(i int, result1 metrics.Histogram) {
	fake.withMutex.Lock()
	defer fake.withMutex.Unlock()
	fake.WithStub = nil
	if fake.withReturnsOnCall == nil {
		fake.withReturnsOnCall = make(map[int]struct {
			result1 metrics.Histogram
		})
	}
	fake.withReturnsOnCall[i] = struct {
		result1 metrics.Histogram
	}{result1}
}

func (fake *Histogram) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.observeMutex.RLock()
	defer fake.observeMutex.RUnlock()
	fake.withMutex.RLock()
	defer fake.withMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *Histogram) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}

var _ metrics.Histogram = new(Histogram)

/*⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓⛓*/

type Provider struct {
	NewCounterStub        func(metrics.CounterOpts) metrics.Counter
	newCounterMutex       sync.RWMutex
	newCounterArgsForCall []struct {
		arg1 metrics.CounterOpts
	}
	newCounterReturns struct {
		result1 metrics.Counter
	}
	newCounterReturnsOnCall map[int]struct {
		result1 metrics.Counter
	}
	NewGaugeStub        func(metrics.GaugeOpts) metrics.Gauge
	newGaugeMutex       sync.RWMutex
	newGaugeArgsForCall []struct {
		arg1 metrics.GaugeOpts
	}
	newGaugeReturns struct {
		result1 metrics.Gauge
	}
	newGaugeReturnsOnCall map[int]struct {
		result1 metrics.Gauge
	}
	NewHistogramStub        func(metrics.HistogramOpts) metrics.Histogram
	newHistogramMutex       sync.RWMutex
	newHistogramArgsForCall []struct {
		arg1 metrics.HistogramOpts
	}
	newHistogramReturns struct {
		result1 metrics.Histogram
	}
	newHistogramReturnsOnCall map[int]struct {
		result1 metrics.Histogram
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *Provider) NewCounter(arg1 metrics.CounterOpts) metrics.Counter {
	fake.newCounterMutex.Lock()
	ret, specificReturn := fake.newCounterReturnsOnCall[len(fake.newCounterArgsForCall)]
	fake.newCounterArgsForCall = append(fake.newCounterArgsForCall, struct {
		arg1 metrics.CounterOpts
	}{arg1})
	fake.recordInvocation("NewCounter", []interface{}{arg1})
	fake.newCounterMutex.Unlock()
	if fake.NewCounterStub != nil {
		return fake.NewCounterStub(arg1)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.newCounterReturns
	return fakeReturns.result1
}

func (fake *Provider) NewCounterCallCount() int {
	fake.newCounterMutex.RLock()
	defer fake.newCounterMutex.RUnlock()
	return len(fake.newCounterArgsForCall)
}

func (fake *Provider) NewCounterCalls(stub func(metrics.CounterOpts) metrics.Counter) {
	fake.newCounterMutex.Lock()
	defer fake.newCounterMutex.Unlock()
	fake.NewCounterStub = stub
}

func (fake *Provider) NewCounterArgsForCall(i int) metrics.CounterOpts {
	fake.newCounterMutex.RLock()
	defer fake.newCounterMutex.RUnlock()
	argsForCall := fake.newCounterArgsForCall[i]
	return argsForCall.arg1
}

func (fake *Provider) NewCounterReturns(result1 metrics.Counter) {
	fake.newCounterMutex.Lock()
	defer fake.newCounterMutex.Unlock()
	fake.NewCounterStub = nil
	fake.newCounterReturns = struct {
		result1 metrics.Counter
	}{result1}
}

func (fake *Provider) NewCounterReturnsOnCall(i int, result1 metrics.Counter) {
	fake.newCounterMutex.Lock()
	defer fake.newCounterMutex.Unlock()
	fake.NewCounterStub = nil
	if fake.newCounterReturnsOnCall == nil {
		fake.newCounterReturnsOnCall = make(map[int]struct {
			result1 metrics.Counter
		})
	}
	fake.newCounterReturnsOnCall[i] = struct {
		result1 metrics.Counter
	}{result1}
}

func (fake *Provider) NewGauge(arg1 metrics.GaugeOpts) metrics.Gauge {
	fake.newGaugeMutex.Lock()
	ret, specificReturn := fake.newGaugeReturnsOnCall[len(fake.newGaugeArgsForCall)]
	fake.newGaugeArgsForCall = append(fake.newGaugeArgsForCall, struct {
		arg1 metrics.GaugeOpts
	}{arg1})
	fake.recordInvocation("NewGauge", []interface{}{arg1})
	fake.newGaugeMutex.Unlock()
	if fake.NewGaugeStub != nil {
		return fake.NewGaugeStub(arg1)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.newGaugeReturns
	return fakeReturns.result1
}

func (fake *Provider) NewGaugeCallCount() int {
	fake.newGaugeMutex.RLock()
	defer fake.newGaugeMutex.RUnlock()
	return len(fake.newGaugeArgsForCall)
}

func (fake *Provider) NewGaugeCalls(stub func(metrics.GaugeOpts) metrics.Gauge) {
	fake.newGaugeMutex.Lock()
	defer fake.newGaugeMutex.Unlock()
	fake.NewGaugeStub = stub
}

func (fake *Provider) NewGaugeArgsForCall(i int) metrics.GaugeOpts {
	fake.newGaugeMutex.RLock()
	defer fake.newGaugeMutex.RUnlock()
	argsForCall := fake.newGaugeArgsForCall[i]
	return argsForCall.arg1
}

func (fake *Provider) NewGaugeReturns(result1 metrics.Gauge) {
	fake.newGaugeMutex.Lock()
	defer fake.newGaugeMutex.Unlock()
	fake.NewGaugeStub = nil
	fake.newGaugeReturns = struct {
		result1 metrics.Gauge
	}{result1}
}

func (fake *Provider) NewGaugeReturnsOnCall(i int, result1 metrics.Gauge) {
	fake.newGaugeMutex.Lock()
	defer fake.newGaugeMutex.Unlock()
	fake.NewGaugeStub = nil
	if fake.newGaugeReturnsOnCall == nil {
		fake.newGaugeReturnsOnCall = make(map[int]struct {
			result1 metrics.Gauge
		})
	}
	fake.newGaugeReturnsOnCall[i] = struct {
		result1 metrics.Gauge
	}{result1}
}

func (fake *Provider) NewHistogram(arg1 metrics.HistogramOpts) metrics.Histogram {
	fake.newHistogramMutex.Lock()
	ret, specificReturn := fake.newHistogramReturnsOnCall[len(fake.newHistogramArgsForCall)]
	fake.newHistogramArgsForCall = append(fake.newHistogramArgsForCall, struct {
		arg1 metrics.HistogramOpts
	}{arg1})
	fake.recordInvocation("NewHistogram", []interface{}{arg1})
	fake.newHistogramMutex.Unlock()
	if fake.NewHistogramStub != nil {
		return fake.NewHistogramStub(arg1)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.newHistogramReturns
	return fakeReturns.result1
}

func (fake *Provider) NewHistogramCallCount() int {
	fake.newHistogramMutex.RLock()
	defer fake.newHistogramMutex.RUnlock()
	return len(fake.newHistogramArgsForCall)
}

func (fake *Provider) NewHistogramCalls(stub func(metrics.HistogramOpts) metrics.Histogram) {
	fake.newHistogramMutex.Lock()
	defer fake.newHistogramMutex.Unlock()
	fake.NewHistogramStub = stub
}

func (fake *Provider) NewHistogramArgsForCall(i int) metrics.HistogramOpts {
	fake.newHistogramMutex.RLock()
	defer fake.newHistogramMutex.RUnlock()
	argsForCall := fake.newHistogramArgsForCall[i]
	return argsForCall.arg1
}

func (fake *Provider) NewHistogramReturns(result1 metrics.Histogram) {
	fake.newHistogramMutex.Lock()
	defer fake.newHistogramMutex.Unlock()
	fake.NewHistogramStub = nil
	fake.newHistogramReturns = struct {
		result1 metrics.Histogram
	}{result1}
}

func (fake *Provider) NewHistogramReturnsOnCall(i int, result1 metrics.Histogram) {
	fake.newHistogramMutex.Lock()
	defer fake.newHistogramMutex.Unlock()
	fake.NewHistogramStub = nil
	if fake.newHistogramReturnsOnCall == nil {
		fake.newHistogramReturnsOnCall = make(map[int]struct {
			result1 metrics.Histogram
		})
	}
	fake.newHistogramReturnsOnCall[i] = struct {
		result1 metrics.Histogram
	}{result1}
}

func (fake *Provider) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.newCounterMutex.RLock()
	defer fake.newCounterMutex.RUnlock()
	fake.newGaugeMutex.RLock()
	defer fake.newGaugeMutex.RUnlock()
	fake.newHistogramMutex.RLock()
	defer fake.newHistogramMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *Provider) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}

var _ metrics.Provider = new(Provider)
