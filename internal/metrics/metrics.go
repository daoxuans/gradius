package metrics

import (
	"sync"
	"sync/atomic"
	"time"
)

// Metrics 收集RADIUS服务器性能指标
type Metrics struct {
	// 认证相关指标
	TotalAuthRequests uint64
	SuccessfulAuths   uint64
	FailedAuths       uint64
	ActiveConnections int64

	// 计费相关指标
	TotalAcctRequests uint64
	SuccessfulAcct    uint64
	FailedAcct        uint64

	// 性能指标
	authLatencies []time.Duration
	acctLatencies []time.Duration
	mu            sync.RWMutex
}

func New() *Metrics {
	return &Metrics{
		authLatencies: make([]time.Duration, 0, 1000),
		acctLatencies: make([]time.Duration, 0, 1000),
	}
}

func (m *Metrics) RecordAuthRequest(success bool, duration time.Duration) {
	atomic.AddUint64(&m.TotalAuthRequests, 1)
	if success {
		atomic.AddUint64(&m.SuccessfulAuths, 1)
	} else {
		atomic.AddUint64(&m.FailedAuths, 1)
	}

	m.mu.Lock()
	m.authLatencies = append(m.authLatencies, duration)
	if len(m.authLatencies) > 1000 {
		m.authLatencies = m.authLatencies[1:]
	}
	m.mu.Unlock()
}

func (m *Metrics) RecordAcctRequest(success bool, duration time.Duration) {
	atomic.AddUint64(&m.TotalAcctRequests, 1)
	if success {
		atomic.AddUint64(&m.SuccessfulAcct, 1)
	} else {
		atomic.AddUint64(&m.FailedAcct, 1)
	}

	m.mu.Lock()
	m.acctLatencies = append(m.acctLatencies, duration)
	if len(m.acctLatencies) > 1000 {
		m.acctLatencies = m.acctLatencies[1:]
	}
	m.mu.Unlock()
}

func (m *Metrics) IncrementConnections() {
	atomic.AddInt64(&m.ActiveConnections, 1)
}

func (m *Metrics) DecrementConnections() {
	atomic.AddInt64(&m.ActiveConnections, -1)
}

func (m *Metrics) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var authAvgLatency time.Duration
	if len(m.authLatencies) > 0 {
		var total time.Duration
		for _, d := range m.authLatencies {
			total += d
		}
		authAvgLatency = total / time.Duration(len(m.authLatencies))
	}

	var acctAvgLatency time.Duration
	if len(m.acctLatencies) > 0 {
		var total time.Duration
		for _, d := range m.acctLatencies {
			total += d
		}
		acctAvgLatency = total / time.Duration(len(m.acctLatencies))
	}

	return map[string]interface{}{
		"total_auth_requests": atomic.LoadUint64(&m.TotalAuthRequests),
		"successful_auths":    atomic.LoadUint64(&m.SuccessfulAuths),
		"failed_auths":        atomic.LoadUint64(&m.FailedAuths),
		"total_acct_requests": atomic.LoadUint64(&m.TotalAcctRequests),
		"successful_acct":     atomic.LoadUint64(&m.SuccessfulAcct),
		"failed_acct":         atomic.LoadUint64(&m.FailedAcct),
		"active_connections":  atomic.LoadInt64(&m.ActiveConnections),
		"avg_auth_latency_ms": authAvgLatency.Milliseconds(),
		"avg_acct_latency_ms": acctAvgLatency.Milliseconds(),
	}
}
