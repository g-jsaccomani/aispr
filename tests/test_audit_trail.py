# -*- coding: utf-8 -*-
"""
Copyright © 2026 Joabson Saccomani (@jsaccomani).
Licensed under the Apache License, Version 2.0.

Unit tests verifying the hash-chained, append-only audit trail:
- Sequential chaining and genesis block hash
- Tamper detection when an entry's payload is altered
- Tamper detection when prev_hash is modified or an entry is deleted
- Integration with scan and report logging
"""

import os
import json
import tempfile
import unittest
from audit.engine.audit_trail import AuditTrail, GENESIS_PREV_HASH


class TestAuditTrail(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_file = os.path.join(self.temp_dir.name, "audit_trail.jsonl")
        self.trail = AuditTrail(log_path=self.log_file)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_genesis_entry_hash_chaining(self):
        """First entry must have genesis prev_hash (64 zeros) and valid entry_hash."""
        e0 = self.trail.log_event("SCAN_START", {"scope": "gcp-proj"})
        self.assertEqual(e0.entry_id, 0)
        self.assertEqual(e0.prev_hash, GENESIS_PREV_HASH)
        self.assertEqual(len(e0.entry_hash), 64)

        # Second entry points to first entry's hash
        e1 = self.trail.log_event("SCAN_COMPLETE", {"findings": 3})
        self.assertEqual(e1.entry_id, 1)
        self.assertEqual(e1.prev_hash, e0.entry_hash)

        # Verify chain validity
        is_valid, err = self.trail.verify_chain()
        self.assertTrue(is_valid, f"Chain should be valid: {err}")
        self.assertIsNone(err)

    def test_tamper_detection_modified_payload(self):
        """Tampering with an entry's payload must invalidate the chain."""
        self.trail.log_event("ASSESSMENT_START", {"client": "Acme"})
        self.trail.log_event("ASSESSMENT_EVAL", {"score": 75.0})
        self.trail.log_event("REPORT_EXPORT", {"format": "pdf"})

        # Verify before tampering
        is_valid, _ = self.trail.verify_chain()
        self.assertTrue(is_valid)

        # Tamper with the second line in the log file
        with open(self.log_file, "r", encoding="utf-8") as f:
            lines = f.readlines()

        data = json.loads(lines[1])
        data["payload"]["score"] = 99.9  # Unauthorized metric inflation!
        lines[1] = json.dumps(data) + "\n"

        with open(self.log_file, "w", encoding="utf-8") as f:
            f.writelines(lines)

        # Verification must now fail
        is_valid, err = self.trail.verify_chain()
        self.assertFalse(is_valid)
        self.assertIn("Corrupted entry hash at index 1", err)

    def test_tamper_detection_broken_chain(self):
        """Altering prev_hash or deleting an entry must break the chain."""
        e0 = self.trail.log_scan("proj-1", "SHADOW_AI", 2)
        e1 = self.trail.log_report("ses-001", "pdf", {"health_score": 82.0})
        e2 = self.trail.log_event("FINAL_SIGNOFF", {"status": "APPROVED"})

        with open(self.log_file, "r", encoding="utf-8") as f:
            lines = f.readlines()

        # Delete middle entry (index 1)
        del lines[1]

        with open(self.log_file, "w", encoding="utf-8") as f:
            f.writelines(lines)

        # Verification must catch sequence break or broken hash pointer
        is_valid, err = self.trail.verify_chain()
        self.assertFalse(is_valid)

    def test_scan_and_report_integration(self):
        """Verify high-level helper methods log typed events correctly."""
        s = self.trail.log_scan("my-gcp-ai", "VERTEX_AUDIT", 4, session_id="ses-100")
        self.assertEqual(s.event_type, "SCAN_EXECUTED")
        self.assertEqual(s.payload["findings_count"], 4)

        r = self.trail.log_report("ses-100", "pdf", {"implementation_coverage": 45.0})
        self.assertEqual(r.event_type, "REPORT_GENERATED")
        self.assertEqual(r.prev_hash, s.entry_hash)

        is_valid, err = self.trail.verify_chain()
        self.assertTrue(is_valid, f"Chain should be valid: {err}")


if __name__ == "__main__":
    unittest.main()
