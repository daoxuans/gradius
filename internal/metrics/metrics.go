package metrics

import (
	"sync/atomic"
	"time"
)

type Metrics struct {
	// 认证相关指标
	TotalAuthRequests uint64
	SuccessfulAuths   uint64
	FailedAuths       uint64

	// 计费相关指标
	TotalAcctRequests uint64
	SuccessfulAcct    uint64
	FailedAcct        uint64

	// 性能指标
	authLatencySum   uint64
	acctLatencySum   uint64
	authLatencyCount uint64
	acctLatencyCount uint64
}

func New() *Metrics {
	return &Metrics{}
}

func (m *Metrics) RecordAuthRequest(success bool, duration time.Duration) {
	atomic.AddUint64(&m.TotalAuthRequests, 1)
	if success {
		atomic.AddUint64(&m.SuccessfulAuths, 1)
	} else {
		atomic.AddUint64(&m.FailedAuths, 1)
	}

	atomic.AddUint64(&m.authLatencySum, uint64(duration.Microseconds()))
	atomic.AddUint64(&m.authLatencyCount, 1)
}

func (m *Metrics) RecordAcctRequest(success bool, duration time.Duration) {
	atomic.AddUint64(&m.TotalAcctRequests, 1)
	if success {
		atomic.AddUint64(&m.SuccessfulAcct, 1)
	} else {
		atomic.AddUint64(&m.FailedAcct, 1)
	}

	atomic.AddUint64(&m.acctLatencySum, uint64(duration.Microseconds()))
	atomic.AddUint64(&m.acctLatencyCount, 1)
}

func (m *Metrics) GetStats() map[string]interface{} {
	authLatencySum := atomic.LoadUint64(&m.authLatencySum)
	authLatencyCount := atomic.LoadUint64(&m.authLatencyCount)
	acctLatencySum := atomic.LoadUint64(&m.acctLatencySum)
	acctLatencyCount := atomic.LoadUint64(&m.acctLatencyCount)

	var authAvgLatency, acctAvgLatency time.Duration
	if authLatencyCount > 0 {
		authAvgLatency = time.Duration(authLatencySum/authLatencyCount) * time.Microsecond
	}
	if acctLatencyCount > 0 {
		acctAvgLatency = time.Duration(acctLatencySum/acctLatencyCount) * time.Microsecond
	}

	return map[string]interface{}{
		"total_auth_requests": atomic.LoadUint64(&m.TotalAuthRequests),
		"successful_auths":    atomic.LoadUint64(&m.SuccessfulAuths),
		"failed_auths":        atomic.LoadUint64(&m.FailedAuths),
		"total_acct_requests": atomic.LoadUint64(&m.TotalAcctRequests),
		"successful_acct":     atomic.LoadUint64(&m.SuccessfulAcct),
		"failed_acct":         atomic.LoadUint64(&m.FailedAcct),
		"avg_auth_latency_ms": authAvgLatency.Milliseconds(),
		"avg_acct_latency_ms": acctAvgLatency.Milliseconds(),
	}
}
