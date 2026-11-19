import unittest
from datetime import datetime, timezone

from empirical_auth_evaluation import build_benign_training_baseline, parse_features


class FeatureSchemaCompatibilityTests(unittest.TestCase):
    def make_row(self, feature_count: int):
        return {
            "_timestamp": datetime(2026, 11, 17, 12, 0, tzinfo=timezone.utc),
            "_feature_count": feature_count,
            "source_ip_hash": "source-hash",
            "user_key_hash": "user-hash",
            "auth_success": True,
        }

    def test_v3_baseline_has_four_dimensions_and_no_utc_hour(self):
        matrix = build_benign_training_baseline([self.make_row(4)])
        self.assertEqual(matrix.shape, (1, 4))
        self.assertEqual(matrix[0].tolist(), [0.0, 0.0, 120.0, 0.0])

    def test_v2_historical_baseline_retains_utc_hour(self):
        matrix = build_benign_training_baseline([self.make_row(5)])
        self.assertEqual(matrix.shape, (1, 5))
        self.assertEqual(matrix[0].tolist(), [0.0, 0.0, 120.0, 0.0, 12.0])

    def test_parser_accepts_each_version_dimension(self):
        self.assertEqual(parse_features("{1,2,3,4}", 4).shape, (4,))
        self.assertEqual(parse_features("{1,2,3,4,5}", 5).shape, (5,))
        with self.assertRaises(ValueError):
            parse_features("{1,2,3,4,5}", 4)


if __name__ == "__main__":
    unittest.main()
