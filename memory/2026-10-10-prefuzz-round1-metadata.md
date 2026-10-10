# Round-1 metadata failure

Symptom: server verification consumed tokens successfully, then packaging raised FileNotFoundError.
Root cause: two finalization paths still used server-round-manifest.json despite selecting next-round-manifest.json earlier.
Fix: both paths now use manifest_name. No crypto, receipt values, or consumed sessions changed.
Regression: test_server_verify_metadata.py replays public receipts at the external worker boundary and runs real packaging for ranks 0 and 1. It failed on rank 1 before the fix and passed afterward. It does not test cryptographic verification.
Status: metadata regression resolved; full protocol remains incomplete. Later candidate issuance needs separate validation.

Validation: Windows metadata regression (both rounds) and 3 client-message tests passed. WSL full discovery ran 39 tests, with 16 failures in preparation/inventory tests. Direct import of prepare_queries confirmed missing numpy in that WSL Python environment. Full-suite success is not claimed. Existing preparation files were not modified.
