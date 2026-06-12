use crate::transaction::tx::Transaction;
use std::collections::HashMap;

/// Maximum total serialized size of all transactions held in the mempool.
/// Prevents an attacker from exhausting node memory by flooding with large txs.
pub const MAX_MEMPOOL_BYTES: usize = 32 * 1024 * 1024; // 32 MB

/// Minimum fee (in arkes) required for a transaction to enter the mempool.
/// Prevents free DoS via fee-less spam transactions.
pub const MIN_FEE_ARKES: u64 = 1_000; // 1,000 arkes ≈ 0.000001 ARKOS

/// Minimum non-zero output value. Outputs below this are dust and rejected.
/// Named after Bitcoin's analogous limit; value reflects the cost of spending
/// a UTXO relative to the fees generated.
pub const DUST_LIMIT_ARKES: u64 = 546;

pub struct Mempool {
    txs: HashMap<String, Transaction>,
    /// Fee in arkes for each transaction (txid → fee).
    fees: HashMap<String, u64>,
    /// Total approximate serialized size of held transactions.
    total_bytes: usize,
}

impl Mempool {
    pub fn new() -> Self {
        Mempool {
            txs: HashMap::new(),
            fees: HashMap::new(),
            total_bytes: 0,
        }
    }

    /// Add a transaction to the mempool.
    ///
    /// Returns `Err` if:
    /// - The fee (input_sum - output_sum) is below `MIN_FEE_ARKES`
    /// - Adding this transaction would exceed `MAX_MEMPOOL_BYTES`
    ///
    /// The `fee` parameter is the pre-computed fee (caller already verified
    /// inputs ≥ outputs in `validate_tx`; pass `input_sum - output_sum`).
    pub fn add_with_fee(&mut self, tx: Transaction, fee: u64) -> Result<String, String> {
        if fee < MIN_FEE_ARKES {
            return Err(format!(
                "transaction fee {} arkes is below minimum {} arkes",
                fee, MIN_FEE_ARKES
            ));
        }
        let tx_size = bincode::serialized_size(&tx).unwrap_or(0) as usize;
        if self.total_bytes + tx_size > MAX_MEMPOOL_BYTES {
            return Err(format!(
                "mempool is full ({}/{} bytes); try again later",
                self.total_bytes, MAX_MEMPOOL_BYTES
            ));
        }
        let txid = tx.txid_hex();
        if self.txs.insert(txid.clone(), tx).is_none() {
            self.total_bytes += tx_size;
            self.fees.insert(txid.clone(), fee);
        }
        Ok(txid)
    }

    /// Add without fee checking — used internally for coinbase and by tests.
    pub fn add(&mut self, tx: Transaction) -> String {
        let tx_size = bincode::serialized_size(&tx).unwrap_or(0) as usize;
        let txid = tx.txid_hex();
        if self.txs.insert(txid.clone(), tx).is_none() {
            self.total_bytes += tx_size;
            self.fees.insert(txid.clone(), 0);
        }
        txid
    }

    pub fn remove(&mut self, txid: &str) {
        if let Some(tx) = self.txs.remove(txid) {
            let tx_size = bincode::serialized_size(&tx).unwrap_or(0) as usize;
            self.total_bytes = self.total_bytes.saturating_sub(tx_size);
            self.fees.remove(txid);
        }
    }

    pub fn get(&self, txid: &str) -> Option<&Transaction> {
        self.txs.get(txid)
    }

    pub fn fee_for(&self, txid: &str) -> u64 {
        self.fees.get(txid).copied().unwrap_or(0)
    }

    /// Return up to `limit` transactions ordered by **fee rate** (arkes per byte)
    /// descending — highest-value transactions are included first.
    ///
    /// Ties are broken by txid for determinism.  Miners naturally favour this
    /// ordering because it maximises fee income per block weight.
    pub fn take(&self, limit: usize) -> Vec<&Transaction> {
        let mut entries: Vec<(&String, &Transaction)> = self.txs.iter().collect();
        entries.sort_unstable_by(|(txid_a, tx_a), (txid_b, tx_b)| {
            let size_a = bincode::serialized_size(tx_a).unwrap_or(1).max(1);
            let size_b = bincode::serialized_size(tx_b).unwrap_or(1).max(1);
            let fee_a = self.fees.get(*txid_a).copied().unwrap_or(0);
            let fee_b = self.fees.get(*txid_b).copied().unwrap_or(0);
            // fee_rate_a = fee_a / size_a  — compare without floating point:
            // fee_a * size_b vs fee_b * size_a
            let lhs = fee_a.saturating_mul(size_b);
            let rhs = fee_b.saturating_mul(size_a);
            rhs.cmp(&lhs) // descending
                .then_with(|| txid_a.cmp(txid_b)) // tie-break: ascending txid
        });
        entries.into_iter().take(limit).map(|(_, tx)| tx).collect()
    }

    /// Alias for `take` — returns references without removing anything.
    pub fn peek(&self, limit: usize) -> Vec<&Transaction> {
        self.take(limit)
    }

    pub fn len(&self) -> usize {
        self.txs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    pub fn contains(&self, txid: &str) -> bool {
        self.txs.contains_key(txid)
    }

    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }
}
