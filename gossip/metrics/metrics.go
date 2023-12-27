package metrics

import "github.com/11090815/hyperchain/common/metrics"

type GossipMetrics struct {
	StateMetrics      *StateMetrics
	ElectionMetrics   *ElectionMetrics
	CommMetrics       *CommMetrics
	MembershipMetrics *MembershipMetrics
	PrivdataMetrics   *PrivdataMetrics
}

func NewGossipMetrics(p metrics.Provider) *GossipMetrics {
	return &GossipMetrics{
		StateMetrics:      newStateMetrics(p),
		ElectionMetrics:   newElectionMetrics(p),
		CommMetrics:       newCommMetrics(p),
		MembershipMetrics: newMembershipMetrics(p),
		PrivdataMetrics:   newPrivdataMetrics(p),
	}
}

type StateMetrics struct {
	Height            metrics.Gauge
	CommitDuration    metrics.Histogram
	PayloadBufferSize metrics.Gauge
}

var (
	HeightOpts = metrics.GaugeOpts{
		Namespace:    "gossip",
		Subsystem:    "state",
		Name:         "height",
		Help:         "Current ledger height",
		LabelNames:   []string{"channel"},
		StatsdFormat: "%{#fqname}.%{channel}",
	}

	CommitDurationOpts = metrics.HistogramOpts{
		Namespace:    "gossip",
		Subsystem:    "state",
		Name:         "commit_duration",
		Help:         "Time it takes to commit a block in seconds",
		LabelNames:   []string{"channel"},
		StatsdFormat: "%{#fqname}.%{channel}",
	}

	PayloadBufferSizeOpts = metrics.GaugeOpts{
		Namespace:    "gossip",
		Subsystem:    "state",
		Name:         "payload_buffer_size",
		Help:         "Size of the payload buffer",
		LabelNames:   []string{"channel"},
		StatsdFormat: "%{#fqname}.%{channel}",
	}
)

func newStateMetrics(p metrics.Provider) *StateMetrics {
	return &StateMetrics{
		Height:            p.NewGauge(HeightOpts),
		CommitDuration:    p.NewHistogram(CommitDurationOpts),
		PayloadBufferSize: p.NewGauge(PayloadBufferSizeOpts),
	}
}

type ElectionMetrics struct {
	Declaration metrics.Gauge
}

var (
	DeclarationOpts = metrics.GaugeOpts{
		Namespace:    "gossip",
		Subsystem:    "leader_election",
		Name:         "declaration",
		Help:         "Declare this peer is leader or not, peer is leader (1) or follower (0)",
		LabelNames:   []string{"channel"},
		StatsdFormat: "%{#fqname}.%{channel}",
	}
)

func newElectionMetrics(p metrics.Provider) *ElectionMetrics {
	return &ElectionMetrics{
		Declaration: p.NewGauge(DeclarationOpts),
	}
}

type CommMetrics struct {
	SentMessages     metrics.Counter
	BufferOverflow   metrics.Counter
	ReceivedMessages metrics.Counter
}

var (
	SentMessagesOpts = metrics.CounterOpts{
		Namespace:    "gossip",
		Subsystem:    "comm",
		Name:         "messages_sent",
		Help:         "Number of messages sent",
		StatsdFormat: "%{#fqname}",
	}

	BufferOverflowOpts = metrics.CounterOpts{
		Namespace:    "gossip",
		Subsystem:    "comm",
		Name:         "overflow_count",
		Help:         "Number of outgoing queue buffer overflows",
		StatsdFormat: "%{#fqname}",
	}

	ReceivedMessagesOpts = metrics.CounterOpts{
		Namespace:    "gossip",
		Subsystem:    "comm",
		Name:         "messages_received",
		Help:         "Number of messages received",
		StatsdFormat: "%{#fqname}",
	}
)

func newCommMetrics(p metrics.Provider) *CommMetrics {
	return &CommMetrics{
		SentMessages:     p.NewCounter(SentMessagesOpts),
		BufferOverflow:   p.NewCounter(BufferOverflowOpts),
		ReceivedMessages: p.NewCounter(ReceivedMessagesOpts),
	}
}

type MembershipMetrics struct {
	Total metrics.Gauge
}

var (
	TotalOpts = metrics.GaugeOpts{
		Namespace:    "gossip",
		Subsystem:    "membership",
		Name:         "total_peers_known",
		Help:         "Total known peers",
		LabelNames:   []string{"channel"},
		StatsdFormat: "%{#fqname}.%{channel}",
	}
)

func newMembershipMetrics(p metrics.Provider) *MembershipMetrics {
	return &MembershipMetrics{
		Total: p.NewGauge(TotalOpts),
	}
}

type PrivdataMetrics struct {
	ValidationDuration          metrics.Histogram
	ListMissingPrivdataDuration metrics.Histogram
	FetchDuration               metrics.Histogram
	CommitPrivdataDuration      metrics.Histogram
	PurgeDuration               metrics.Histogram
	SendDuration                metrics.Histogram
	ReconciliationDuration      metrics.Histogram
	PullDuration                metrics.Histogram
	RetrieveDuration            metrics.Histogram
}

var (
	ValidationDurationOpts = metrics.HistogramOpts{
		Namespace:    "gossip",
		Subsystem:    "privdata",
		Name:         "validation_duration",
		Help:         "Time it takes to validate a block (in seconds)",
		LabelNames:   []string{"channel"},
		StatsdFormat: "%{#fqname}.%{channel}",
	}

	ListMissingPrivdataDurationOpts = metrics.HistogramOpts{
		Namespace:    "gossip",
		Subsystem:    "privdata",
		Name:         "list_missing_duration",
		Help:         "Time it takes to list the missing private data (in seconds)",
		LabelNames:   []string{"channel"},
		StatsdFormat: "%{#fqname}.%{channel}",
	}

	FetchDurationOpts = metrics.HistogramOpts{
		Namespace:    "gossip",
		Subsystem:    "privdata",
		Name:         "fetch_duration",
		Help:         "Time it takes to fetch missing private data from peers (in seconds)",
		LabelNames:   []string{"channel"},
		StatsdFormat: "%{#fqname}.%{channel}",
	}

	CommitPrivdataDurationOpts = metrics.HistogramOpts{
		Namespace:    "gossip",
		Subsystem:    "privdata",
		Name:         "commit_private_data_duration",
		Help:         "Time it takes to commit private data and the corresponding block (in seconds)",
		LabelNames:   []string{"channel"},
		StatsdFormat: "%{#fqname}.%{channel}",
	}

	PurgeDurationOpts = metrics.HistogramOpts{
		Namespace:    "gossip",
		Subsystem:    "privdata",
		Name:         "purge_private_data_duration",
		Help:         "Time it takes to purge private data (in seconds)",
		LabelNames:   []string{"channel"},
		StatsdFormat: "%{#fqname}.%{channel}",
	}

	SendDurationOpts = metrics.HistogramOpts{
		Namespace:    "gossip",
		Subsystem:    "privdata",
		Name:         "commit_private_data_duration",
		Help:         "Time it takes to commit private data and the corresponding block (in seconds)",
		LabelNames:   []string{"channel"},
		StatsdFormat: "%{#fqname}.%{channel}",
	}

	ReconciliationDurationOpts = metrics.HistogramOpts{
		Namespace:    "gossip",
		Subsystem:    "privdata",
		Name:         "reconciliation_duration",
		Help:         "Time it takes for reconciliation to complete (inseconds)",
		LabelNames:   []string{"channel"},
		StatsdFormat: "%{#fqname}.%{channel}",
	}

	PullDurationOpts = metrics.HistogramOpts{
		Namespace:    "gossip",
		Subsystem:    "privdata",
		Name:         "pull_missing_private_data_duration",
		Help:         "Time it takes to pull a missing private data element (in seconds)",
		LabelNames:   []string{"channel"},
		StatsdFormat: "%{#fqname}.%{channel}",
	}

	RetrieveDurationOpts = metrics.HistogramOpts{
		Namespace:    "gossip",
		Subsystem:    "privdata",
		Name:         "retrieve_missing_private_data_duration",
		Help:         "Time it takes to retrieve missing private data elements from the ledger (in seconds)",
		LabelNames:   []string{"channel"},
		StatsdFormat: "%{#fqname}.%{channel}",
	}
)

func newPrivdataMetrics(p metrics.Provider) *PrivdataMetrics {
	return &PrivdataMetrics{
		ValidationDuration:          p.NewHistogram(ValidationDurationOpts),
		ListMissingPrivdataDuration: p.NewHistogram(ListMissingPrivdataDurationOpts),
		FetchDuration:               p.NewHistogram(FetchDurationOpts),
		CommitPrivdataDuration:      p.NewHistogram(CommitDurationOpts),
		PurgeDuration:               p.NewHistogram(PurgeDurationOpts),
		SendDuration:                p.NewHistogram(SendDurationOpts),
		ReconciliationDuration:      p.NewHistogram(ReconciliationDurationOpts),
		PullDuration:                p.NewHistogram(PullDurationOpts),
		RetrieveDuration:            p.NewHistogram(RetrieveDurationOpts),
	}
}
