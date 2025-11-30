# Adaptive Load Balancing Guide

## Overview

The adaptive load balancing feature dynamically adjusts traffic distribution based on real-time server load metrics. Instead of simple round-robin, it uses **weighted selection** where servers with lower load receive more traffic.

## How It Works

### 1. **Statistics Polling**
- Periodically polls OpenFlow port statistics from the switch
- Collects traffic metrics (bytes, packets) for each backend server port
- Calculates load metrics for each backend

### 2. **Load Calculation**
- Load = (Backend Traffic) / (Total Traffic)
- Normalized to 0.0 (no load) to 1.0 (maximum load)
- Based on both incoming (requests) and outgoing (responses) traffic

### 3. **Weight Adjustment**
- Weight = 1.0 / (Load + ε) + 1.0
- **Inverse relationship**: Lower load → Higher weight → More traffic
- Weights are normalized to maintain fair distribution

### 4. **Weighted Selection**
- Uses `random.choices()` with weights for selection
- Servers with higher weights are more likely to be selected
- Still maintains randomness for distribution

## Enabling Adaptive Load Balancing

### Step 1: Enable in Configuration

Edit `ryu_app_lb_fw.py`:

```python
# Adaptive Load Balancing Configuration
ENABLE_ADAPTIVE_LB = True  # Change from False to True
STATS_POLL_INTERVAL = 5    # Poll every 5 seconds
ADAPTIVE_THRESHOLD = 0.8   # Load threshold (currently not used, reserved for future)
```

### Step 2: Restart Ryu Controller

```bash
# Stop current controller (Ctrl+C)
# Restart with adaptive LB enabled
ryu-manager ryu_app_lb_fw.py --verbose
```

### Step 3: Verify It's Working

Check Ryu logs for messages like:
```
Started adaptive load balancing polling thread
Adjusted weights: 10.0.0.11: 1.05, 10.0.0.12: 0.95, 10.0.0.13: 1.00
Adaptive LB: Selected 10.0.0.11 (load=0.30, weight=1.05)
```

## Configuration Options

### Polling Interval

```python
STATS_POLL_INTERVAL = 5  # Seconds between statistics polls
```

- **Lower values** (1-3s): More responsive, but higher controller overhead
- **Higher values** (10-30s): Less overhead, but slower adaptation
- **Recommended**: 5-10 seconds for most scenarios

### Load Calculation Method

Currently uses **port statistics** (total bytes):
- `tx_bytes + rx_bytes` on backend server ports
- Simple and effective for most cases

Future enhancements could use:
- Flow statistics (per-connection metrics)
- Response time (RTT measurements)
- Error rates
- CPU/memory metrics (if available)

## Testing Adaptive Load Balancing

### Test 1: Baseline (Equal Load)

```bash
# From Mininet CLI
mininet> h1 bash -c 'for i in {1..20}; do curl -s 10.0.0.100 > /dev/null; sleep 0.1; done'

# Check distribution (should be roughly equal)
mininet> h4 tail -20 /tmp/h4_http.log | wc -l
mininet> h5 tail -20 /tmp/h5_http.log | wc -l
mininet> h6 tail -20 /tmp/h6_http.log | wc -l
```

### Test 2: Create Load Imbalance

```bash
# Generate heavy load on h4 (server 1)
mininet> h1 bash -c 'while true; do curl -s 10.0.0.11 > /dev/null; done' &

# Make requests to VIP
mininet> h2 bash -c 'for i in {1..30}; do curl -s 10.0.0.100 > /dev/null; sleep 0.2; done'

# Check distribution - h5 and h6 should get more requests
mininet> h4 tail -30 /tmp/h4_http.log | wc -l  # Should be fewer
mininet> h5 tail -30 /tmp/h5_http.log | wc -l  # Should be more
mininet> h6 tail -30 /tmp/h6_http.log | wc -l   # Should be more
```

### Test 3: Monitor Weight Changes

Watch Ryu controller logs in real-time:

```bash
# In Ryu terminal, you should see:
# Adjusted weights: 10.0.0.11: 0.85, 10.0.0.12: 1.10, 10.0.0.13: 1.05
```

## How Adaptive Differs from Round-Robin

### Round-Robin (Default)
```
Request 1 → h4
Request 2 → h5
Request 3 → h6
Request 4 → h4
Request 5 → h5
...
```
- **Deterministic**: Always cycles through servers
- **Fair**: Equal distribution regardless of load
- **Simple**: No overhead

### Adaptive (Weighted)
```
Request 1 → h4 (weight: 1.0)
Request 2 → h5 (weight: 1.0)
Request 3 → h6 (weight: 1.0)
... (h4 gets overloaded) ...
Request 10 → h5 (weight: 1.2) ← Higher probability
Request 11 → h6 (weight: 1.2) ← Higher probability
Request 12 → h5 (weight: 1.2)
...
```
- **Dynamic**: Adjusts based on real-time load
- **Efficient**: Routes traffic away from overloaded servers
- **Intelligent**: Responds to traffic patterns

## Algorithm Details

### Weight Calculation Formula

```python
weight = 1.0 / (load + epsilon) + 1.0
```

Where:
- `load` = Normalized traffic load (0.0 to 1.0)
- `epsilon` = 0.1 (prevents division by zero)
- `+ 1.0` = Ensures minimum weight

**Example:**
- Server with 0.0 load → weight = 1.0 / 0.1 + 1.0 = **11.0**
- Server with 0.5 load → weight = 1.0 / 0.6 + 1.0 = **2.67**
- Server with 0.9 load → weight = 1.0 / 1.0 + 1.0 = **2.0**

### Selection Probability

```python
probability = weight / sum(all_weights)
```

**Example with 3 servers:**
- Weights: [11.0, 2.67, 2.0]
- Sum: 15.67
- Probabilities: [70.2%, 17.0%, 12.8%]

## Performance Considerations

### Overhead
- **Statistics polling**: Minimal (every 5 seconds)
- **Weight calculation**: Negligible (simple math)
- **Selection**: Slightly more CPU than round-robin (random.choices)

### Responsiveness
- **Adaptation delay**: Up to `STATS_POLL_INTERVAL` seconds
- **Smoothing**: Load is cumulative, so changes are gradual
- **Stability**: Weights don't change drastically between polls

## Troubleshooting

### Issue: Weights Not Changing

**Symptoms**: Logs show same weights repeatedly

**Solutions**:
1. Check if statistics are being collected:
   ```python
   # Add debug logging in _port_stats_reply_handler
   self.logger.info("Port stats received: %s", self.port_stats)
   ```

2. Verify backend ports are learned:
   ```python
   # Check if backend_info['port'] is set
   self.logger.info("Backend ports: %s", backend_ports)
   ```

3. Ensure traffic is flowing to backends

### Issue: Too Aggressive Rebalancing

**Symptoms**: Traffic shifts too quickly between servers

**Solutions**:
1. Increase `STATS_POLL_INTERVAL` (e.g., 10-15 seconds)
2. Add smoothing factor to weight calculation
3. Use exponential moving average for load calculation

### Issue: One Server Still Overloaded

**Symptoms**: Even with adaptive LB, one server gets most traffic

**Solutions**:
1. Check if weights are being calculated correctly
2. Verify port statistics are accurate
3. Consider using flow statistics instead of port statistics
4. Add minimum/maximum weight bounds

## Advanced Customization

### Custom Load Metric

Modify `_calculate_backend_load()` to use different metrics:

```python
def _calculate_backend_load(self, dpid):
    # Example: Use only response traffic (tx_bytes)
    for backend_ip, port_no in backend_ports.items():
        if port_no in self.port_stats[dpid]:
            port_stat = self.port_stats[dpid][port_no]
            # Use only outgoing bytes (server responses)
            traffic = port_stat['tx_bytes']
            # ... rest of calculation
```

### Weight Bounds

Add minimum/maximum weight limits:

```python
def _adjust_weights(self):
    # ... existing code ...
    
    # Apply bounds
    MIN_WEIGHT = 0.5
    MAX_WEIGHT = 2.0
    for backend_ip in self.backend_list:
        weight = self.backend_weights[backend_ip]
        weight = max(MIN_WEIGHT, min(MAX_WEIGHT, weight))
        self.backend_weights[backend_ip] = weight
```

### Exponential Moving Average

Smooth load calculations over time:

```python
# In __init__
self.backend_load_ema = {}  # Exponential moving average
ALPHA = 0.3  # Smoothing factor (0.0-1.0)

# In _calculate_backend_load
for backend_ip in self.backend_list:
    current_load = traffic / total_traffic
    if backend_ip not in self.backend_load_ema:
        self.backend_load_ema[backend_ip] = current_load
    else:
        # EMA: new = alpha * current + (1-alpha) * old
        self.backend_load_ema[backend_ip] = (
            ALPHA * current_load + 
            (1 - ALPHA) * self.backend_load_ema[backend_ip]
        )
    self.backend_load[backend_ip] = self.backend_load_ema[backend_ip]
```

## Comparison: Round-Robin vs Adaptive

| Feature | Round-Robin | Adaptive |
|---------|-------------|----------|
| **Complexity** | Simple | Moderate |
| **Overhead** | None | Low (statistics polling) |
| **Fairness** | Perfect (equal) | Dynamic (load-based) |
| **Responsiveness** | N/A | Configurable (poll interval) |
| **Use Case** | Equal capacity servers | Variable capacity/load |

## Best Practices

1. **Start with Round-Robin**: Use adaptive only if you have variable server capacity or load
2. **Monitor Performance**: Watch Ryu logs to ensure weights are reasonable
3. **Tune Polling Interval**: Balance responsiveness vs overhead
4. **Test Under Load**: Verify adaptive behavior with realistic traffic patterns
5. **Set Bounds**: Consider minimum/maximum weights to prevent extreme distributions

## Future Enhancements

Potential improvements:
- [ ] Response time-based load calculation
- [ ] Health check integration (remove failed servers)
- [ ] Machine learning for predictive load balancing
- [ ] Multi-metric load calculation (bytes + packets + errors)
- [ ] Configurable weight calculation algorithms
- [ ] REST API for dynamic weight adjustment

