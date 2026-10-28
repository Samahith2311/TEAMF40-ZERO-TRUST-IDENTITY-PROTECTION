# Risk-Adaptive mTLS Decision Cache Benchmark Report

**Benchmark Profile:** QUICK (200 requests evaluated)  
**Target Architecture:** FastAPI + In-Memory Decision Cache + CertBindingStore  
**Date:** 2026-10-28 20:36:21Z

## Summary of Decision Latency & Throughput

| Decision Path | Mean Latency | p50 Latency | p95 Latency | p99 Latency | Throughput |
|---|---|---|---|---|---|
| **Fast Path (Cached Low-Risk)** | `0.0102 ms` | `0.0101 ms` | `0.0106 ms` | `0.0122 ms` | **97,976.8 req/sec** |
| **Full Path (Rescore & Policy)** | `0.0216 ms` | `0.0155 ms` | `0.0396 ms` | `0.0944 ms` | **46,207.5 req/sec** |
| **Mismatch Path (DET-06 Revoke)** | `0.0205 ms` | `0.0157 ms` | `0.0288 ms` | `0.0344 ms` | **48,847.2 req/sec** |

### Key Findings
1. **Speedup Factor:** The Fast Path decision cache achieves a **2.1x speedup** over the full risk-rescoring pipeline.
2. **Deterministic Mismatch Rejection:** When an attacker presents a mismatched certificate, the decision cache is immediately invalidated, and the engine executes the full risk escalation path within `0.0205 ms`.
3. **No Validation Bypass:** Full peer certificate validation is strictly performed on every TLS connection; the fast path accelerates the risk-evaluation engine, not the underlying TLS handshake.
