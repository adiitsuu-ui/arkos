
/// Target block time in seconds
pub const TARGET_BLOCK_TIME: u64 = 194; // 3 minutes 14 seconds, Pi-themed
/// Difficulty adjusts every N blocks
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u64 = 2016;

/// Compute the median of a slice of timestamps.
fn median_timestamp(ts: &[u64]) -> u64 {
    if ts.is_empty() {
        return 0;
    }
    let mut sorted = ts.to_vec();
    sorted.sort_unstable();
    sorted[sorted.len() / 2]
}

/// Adjust difficulty using **median timestamps** at both endpoints.
///
/// # Time-warp attack mitigation
///
/// Using raw endpoint timestamps allows an attacker to manipulate the reported
/// interval by setting the timestamp of the last block in the period abnormally
/// low (or the first abnormally high), artificially deflating difficulty.
///
/// By computing the median of the 11 timestamps at each endpoint (Bitcoin's
/// MTP rule), an individual block's timestamp can be biased by at most ±5
/// positions in the sorted order, which is insufficient to move the median
/// by more than a handful of seconds.
///
/// # Arguments
/// * `current_bits` - The compact difficulty bits at the period's last block.
/// * `start_timestamps` - Timestamps of the 11 blocks around the period start.
/// * `end_timestamps`   - Timestamps of the 11 blocks around the period end.
pub fn adjust_difficulty(
    current_bits: u32,
    start_timestamps: &[u64],
    end_timestamps: &[u64],
) -> u32 {
    let interval_start_time = median_timestamp(start_timestamps);
    let interval_end_time = median_timestamp(end_timestamps);

    let actual_time = interval_end_time.saturating_sub(interval_start_time);
    let expected_time = TARGET_BLOCK_TIME * DIFFICULTY_ADJUSTMENT_INTERVAL;

    // Clamp to 4× increase / 4× decrease (Bitcoin's rule)
    let actual_clamped = actual_time.max(expected_time / 4).min(expected_time * 4);

    // Scale mantissa
    let exp = (current_bits >> 24) as u64;
    let mantissa = (current_bits & 0x00ff_ffff) as u64;

    // Guard: if mantissa is zero the chain is already at minimum difficulty;
    // any further adjustment would produce 0 bits which means "no difficulty".
    if mantissa == 0 {
        return current_bits;
    }

    let new_mantissa = mantissa * actual_clamped / expected_time;

    // Renormalize if mantissa overflows 3 bytes
    let (new_exp, new_mantissa) = if new_mantissa > 0x00ff_ffff {
        (exp + 1, new_mantissa >> 8)
    } else if new_mantissa < 0x00_0100 && exp > 1 {
        (exp - 1, new_mantissa << 8)
    } else {
        (exp, new_mantissa)
    };

    // Guard again after scaling: never produce a zero mantissa
    let new_mantissa = new_mantissa.max(1).min(0x00ff_ffff) as u32;
    let new_exp = new_exp.min(0x1d) as u32; // cap to avoid astronomically easy difficulty
    (new_exp << 24) | new_mantissa
}

/// Validate that a block's timestamp is within acceptable range
pub fn validate_timestamp(block_ts: u64, median_past_time: u64, network_time: u64) -> bool {
    block_ts > median_past_time && block_ts <= network_time + 7200
}

