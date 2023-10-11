package internal_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/11090815/hyperchain/common/metrics"
	"github.com/11090815/hyperchain/common/metrics/internal"
	"github.com/stretchr/testify/assert"
)

var (
	formatRegexp            = regexp.MustCompile(`%{([#?[:alnum:]_]+)}`)
	invalidLabelValueRegexp = regexp.MustCompile(`[.|:\s]`)
)

func TestRegexp(t *testing.T) {
	tests := []struct {
		format  string
		matches []string
	}{
		{format: "%{#fqname},,,,%{#namespace}", matches: []string{"%{#fqname}", "#fqname", "%{#namespace}", "#namespace"}},
		{format: "_%{#subsystem}___{#namespace}", matches: []string{"%{#subsystem}", "#subsystem"}},
		{format: "prefix.%{#name}"},
	}

	for _, test := range tests {
		matches := formatRegexp.FindAllStringSubmatchIndex(test.format, -1)
		for _, m := range matches {
			start, end := m[0], m[1]
			labelStart, labelEnd := m[2], m[3]

			t.Log(test.format[start:end])
			t.Log(test.format[labelStart:labelEnd])
		}
	}
}

func TestRegexpReplace(t *testing.T) {
	tests := []struct {
		origin   string
		replaced string
	}{
		{origin: "12.34", replaced: "12_34"},
		{origin: "12|34", replaced: "12_34"},
		{origin: "12:34", replaced: "12_34"},
	}

	for _, test := range tests {
		replaced := invalidLabelValueRegexp.ReplaceAllString(test.origin, "_")
		assert.Equal(t, test.replaced, replaced)
	}
}

func TestNamerFormat(t *testing.T) {
	counterOpts := metrics.CounterOpts{
		Namespace:    "www",
		Subsystem:    "metrics",
		Name:         "counter",
		StatsdFormat: "https://%{#namespace}.%{#subsystem}.%{#name}.%{alpha}.bravo.%{bravo}.suffix",
		LabelNames:   []string{"alpha", "bravo"},
	}

	counterNamer := internal.NewCounterNamer(counterOpts)

	format := counterNamer.Format("alpha", "a", "bravo", "b")
	fmt.Println(format) // https://www.metrics.counter.a.bravo.b.suffix
}
