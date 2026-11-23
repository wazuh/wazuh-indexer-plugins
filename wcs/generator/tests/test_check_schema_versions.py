#!/usr/bin/env python3
"""Unit tests for check_schema_versions.py and stamp_schema_versions.py.

Run from the repository root:
    python3 -m unittest discover -s wcs/generator/tests -v
"""

import copy
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), ".."))

import check_schema_versions as check  # noqa: E402
import stamp_schema_versions as stamp  # noqa: E402


def template(fields=None, settings=None, schema=50000, compat=50000, dynamic_templates=None, **extra):
    """Build a small composable template with the given leaf fields and settings."""
    mappings = {
        "dynamic": "strict",
        "date_detection": False,
        "properties": fields if fields is not None else {"name": {"type": "keyword"}},
        "_meta": {"schema_version": schema, "compat_version": compat},
    }
    if dynamic_templates is not None:
        mappings["dynamic_templates"] = dynamic_templates
    doc = {
        "index_patterns": ["test*"],
        "priority": 1,
        "version": schema,
        "template": {
            "settings": settings if settings is not None else {"index": {"number_of_shards": "1"}},
            "mappings": mappings,
        },
    }
    doc.update(extra)
    return doc


class ReleaseNumberTests(unittest.TestCase):
    def test_five_digit_form(self):
        self.assertEqual(stamp.release_number("5.0.0"), 50000)
        self.assertEqual(stamp.release_number("5.2.1"), 50201)
        self.assertEqual(stamp.release_number("5.10.14"), 51014)

    def test_order_matches_release_order(self):
        self.assertLess(stamp.release_number("5.2.1"), stamp.release_number("5.10.14"))
        self.assertLess(stamp.release_number("5.0.10"), stamp.release_number("5.1.0"))

    def test_rejects_other_forms(self):
        for bad in ("5.0", "5.0.0-rc1", "v5.0.0", "5.100.0"):
            with self.assertRaises(ValueError):
                stamp.release_number(bad)


class StampTests(unittest.TestCase):
    def test_writes_version_and_meta(self):
        doc = {"index_patterns": ["x*"], "template": {"mappings": {"properties": {}}}}
        self.assertTrue(stamp.stamp(doc, 50100, 50000))
        self.assertEqual(doc["version"], 50100)
        self.assertEqual(
            doc["template"]["mappings"]["_meta"],
            {"schema_version": 50100, "compat_version": 50000},
        )

    def test_is_idempotent(self):
        doc = template()
        self.assertFalse(stamp.stamp(doc, 50000, 50000))

    def test_load_versions_reads_mapping_settings_meta(self):
        with tempfile.TemporaryDirectory() as root:
            fields = os.path.join(root, "wcs", "stateful", "demo", "fields")
            os.makedirs(fields)
            with open(os.path.join(fields, stamp.VERSION_FILE), "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "dynamic": "strict",
                        "_meta": {"schema_version": 50100, "compat_version": 50000},
                    },
                    handle,
                )
            self.assertEqual(stamp.load_versions(root, "stateful/demo"), (50100, 50000))

            with open(os.path.join(fields, stamp.VERSION_FILE), "w", encoding="utf-8") as handle:
                json.dump({"dynamic": "strict"}, handle)
            with self.assertRaises(ValueError):
                stamp.load_versions(root, "stateful/demo")
            with self.assertRaises(ValueError):
                stamp.load_versions(root, "stateful/missing")

    def test_validate_versions(self):
        self.assertEqual(stamp.validate_versions({"schema_version": 3, "compat_version": 2}, "x"), (3, 2))
        for bad in (
            {"schema_version": 1},
            {"schema_version": "1", "compat_version": 1},
            {"schema_version": 1, "compat_version": 2},
            {"schema_version": 0, "compat_version": 0},
            {"schema_version": True, "compat_version": True},
            [],
        ):
            with self.assertRaises(ValueError):
                stamp.validate_versions(bad, "x")


class FlattenTests(unittest.TestCase):
    def test_properties_and_multi_fields(self):
        fields = check.flatten_fields(
            {
                "properties": {
                    "host": {"properties": {"name": {"type": "keyword", "fields": {"text": {"type": "text"}}}}},
                    "message": {"type": "text"},
                }
            }
        )
        self.assertEqual(fields["host.name"], {"type": "keyword"})
        self.assertEqual(fields["host.name.text"], {"type": "text"})
        self.assertEqual(fields["message"], {"type": "text"})
        self.assertNotIn("host", fields)

    def test_dynamic_templates_by_path(self):
        fields = check.flatten_fields(
            {
                "dynamic_templates": [
                    {"wcs_host_name": {"path_match": "host.name", "mapping": {"type": "keyword"}}},
                    {"strings": {"match_mapping_type": "string", "mapping": {"type": "keyword"}}},
                ]
            }
        )
        self.assertEqual(fields["host.name"], {"type": "keyword"})
        self.assertIn("dynamic_template:strings", fields)

    def test_dynamic_templates_sharing_a_path_are_kept_apart(self):
        rules = [
            {"longs": {"path_match": "value", "match_mapping_type": "long", "mapping": {"type": "long"}}},
            {"strings": {"path_match": "value", "match_mapping_type": "string", "mapping": {"type": "keyword"}}},
        ]
        fields = check.flatten_fields({"dynamic_templates": rules})
        self.assertEqual(len(fields), 2)
        self.assertEqual(
            {v["type"] for v in fields.values()},
            {"long", "keyword"},
        )
        changed = copy.deepcopy(rules)
        changed[0]["longs"]["mapping"]["type"] = "integer"
        _changed, breaking, _compatible = check.classify(
            template(fields={}, dynamic_templates=rules), template(fields={}, dynamic_templates=changed)
        )
        self.assertTrue(breaking)

    def test_settings_prefix(self):
        flat = check.flatten_settings(
            {
                "index": {"number_of_shards": "1", "query.default_field": ["a"]},
                "mapping.total_fields.limit": 1000,
                "plugins.index_state_management.policy_id": "p",
            }
        )
        self.assertEqual(flat["number_of_shards"], "1")
        self.assertEqual(flat["query.default_field"], ["a"])
        self.assertEqual(flat["mapping.total_fields.limit"], 1000)
        self.assertEqual(flat["plugins.index_state_management.policy_id"], "p")


class ClassifyTests(unittest.TestCase):
    def test_unchanged(self):
        changed, breaking, compatible = check.classify(template(), template())
        self.assertFalse(changed)

    def test_added_field_is_compatible(self):
        head = template(fields={"name": {"type": "keyword"}, "other": {"type": "long"}})
        changed, breaking, compatible = check.classify(template(), head)
        self.assertTrue(changed)
        self.assertEqual(breaking, [])
        self.assertEqual(compatible, ["field added: other"])

    def test_added_multi_field_is_compatible(self):
        head = template(fields={"name": {"type": "keyword", "fields": {"text": {"type": "text"}}}})
        _, breaking, compatible = check.classify(template(), head)
        self.assertEqual(breaking, [])
        self.assertEqual(compatible, ["field added: name.text"])

    def test_removed_field_is_breaking(self):
        base = template(fields={"name": {"type": "keyword"}, "other": {"type": "long"}})
        _, breaking, _ = check.classify(base, template())
        self.assertEqual(breaking, ["field removed: other"])

    def test_type_change_is_breaking(self):
        head = template(fields={"name": {"type": "text"}})
        _, breaking, _ = check.classify(template(), head)
        self.assertEqual(breaking, ["field changed: name"])

    def test_analyzer_change_is_breaking(self):
        base = template(fields={"name": {"type": "text", "analyzer": "standard"}})
        head = template(fields={"name": {"type": "text", "analyzer": "english"}})
        _, breaking, _ = check.classify(base, head)
        self.assertEqual(breaking, ["field changed: name"])

    def test_ignore_above_change_is_compatible(self):
        base = template(fields={"name": {"type": "keyword", "ignore_above": 1024}})
        head = template(fields={"name": {"type": "keyword", "ignore_above": 4096}})
        _, breaking, compatible = check.classify(base, head)
        self.assertEqual(breaking, [])
        self.assertEqual(compatible, ["field parameter changed: name"])

    def test_field_moved_to_dynamic_template_is_not_a_change(self):
        base = template(fields={"name": {"type": "keyword"}})
        head = template(
            fields={}, dynamic_templates=[{"wcs_name": {"path_match": "name", "mapping": {"type": "keyword"}}}]
        )
        changed, _, _ = check.classify(base, head)
        self.assertFalse(changed)

    def test_static_setting_is_breaking(self):
        head = template(settings={"index": {"number_of_shards": "3"}})
        _, breaking, _ = check.classify(template(), head)
        self.assertEqual(breaking, ["static setting changed: number_of_shards"])

    def test_codec_is_breaking(self):
        base = template(settings={"index": {"number_of_shards": "1", "codec": "zstd"}})
        head = template(settings={"index": {"number_of_shards": "1", "codec": "best_compression"}})
        _, breaking, _ = check.classify(base, head)
        self.assertEqual(breaking, ["static setting changed: codec"])

    def test_analysis_and_codec_options_are_static(self):
        self.assertTrue(check.is_static_setting("analysis.normalizer.lowercase.type"))
        self.assertTrue(check.is_static_setting("codec.compression_level"))
        self.assertFalse(check.is_static_setting("refresh_interval"))
        base = template(settings={"index": {"number_of_shards": "1"}})
        head = template(
            settings={"index": {"number_of_shards": "1", "analysis": {"normalizer": {"lc": {"type": "custom"}}}}}
        )
        _, breaking, _ = check.classify(base, head)
        self.assertEqual(breaking, ["static setting changed: analysis.normalizer.lc.type"])

    def test_dynamic_setting_is_compatible(self):
        head = template(settings={"index": {"number_of_shards": "1", "refresh_interval": "5s"}})
        _, breaking, compatible = check.classify(template(), head)
        self.assertEqual(breaking, [])
        self.assertEqual(compatible, ["dynamic setting changed: refresh_interval"])

    def test_mapping_dynamic_mode_is_compatible(self):
        head = template()
        head["template"]["mappings"]["dynamic"] = "false"
        _, breaking, compatible = check.classify(template(), head)
        self.assertEqual(breaking, [])
        self.assertEqual(compatible, ["mapping setting changed: dynamic"])

    def test_index_patterns_and_data_stream_are_breaking(self):
        head = template(data_stream={})
        head["index_patterns"] = ["other*"]
        _, breaking, _ = check.classify(template(), head)
        self.assertEqual(breaking, ["index_patterns changed", "data_stream changed"])

    def test_version_metadata_is_not_a_change(self):
        changed, _, _ = check.classify(template(), template(schema=50100, compat=50100))
        self.assertFalse(changed)


class EvaluateTests(unittest.TestCase):
    TARGET = 50100

    def test_unchanged_template_is_ok(self):
        status, change, _ = check.evaluate(template(), template(), self.TARGET)
        self.assertEqual((status, change), (check.OK, "none"))

    def test_changed_without_bump_fails(self):
        head = template(fields={"name": {"type": "keyword"}, "other": {"type": "long"}})
        status, change, reasons = check.evaluate(template(), head, self.TARGET)
        self.assertEqual((status, change), (check.FAIL, "compatible"))
        self.assertIn("schema_version must be 50100, found 50000", reasons[0])

    def test_compatible_change_with_bump_is_ok(self):
        head = template(fields={"name": {"type": "keyword"}, "other": {"type": "long"}}, schema=50100)
        status, change, _ = check.evaluate(template(), head, self.TARGET)
        self.assertEqual((status, change), (check.OK, "compatible"))

    def test_second_change_in_the_same_cycle_is_ok(self):
        base = template(fields={"name": {"type": "keyword"}, "other": {"type": "long"}}, schema=50100)
        head = template(
            fields={"name": {"type": "keyword"}, "other": {"type": "long"}, "third": {"type": "ip"}},
            schema=50100,
        )
        status, _, _ = check.evaluate(base, head, self.TARGET)
        self.assertEqual(status, check.OK)

    def test_breaking_change_without_compat_bump_fails(self):
        head = template(fields={"name": {"type": "text"}}, schema=50100, compat=50000)
        status, change, reasons = check.evaluate(template(), head, self.TARGET)
        self.assertEqual((status, change), (check.FAIL, "breaking"))
        self.assertIn("compat_version must be 50100", reasons[0])

    def test_breaking_change_with_compat_bump_is_ok(self):
        head = template(fields={"name": {"type": "text"}}, schema=50100, compat=50100)
        status, change, _ = check.evaluate(template(), head, self.TARGET)
        self.assertEqual((status, change), (check.OK, "breaking"))

    def test_compatible_change_must_keep_compat(self):
        head = template(fields={"name": {"type": "keyword"}, "other": {"type": "long"}}, schema=50100, compat=50100)
        status, _, reasons = check.evaluate(template(), head, self.TARGET)
        self.assertEqual(status, check.FAIL)
        self.assertIn("compat_version must stay at 50000", reasons[0])

    def test_bump_without_change_warns(self):
        status, change, _ = check.evaluate(template(), template(schema=50100), self.TARGET)
        self.assertEqual((status, change), (check.WARN, "none"))

    def test_new_template_must_carry_target(self):
        self.assertEqual(check.evaluate(None, template(), self.TARGET)[0], check.FAIL)
        self.assertEqual(check.evaluate(None, template(schema=50100, compat=50100), self.TARGET)[0], check.OK)

    def test_inconsistent_template_fails(self):
        head = template()
        head["version"] = 50200
        self.assertEqual(check.evaluate(template(), head, self.TARGET)[0], check.FAIL)
        head = template()
        del head["template"]["mappings"]["_meta"]
        self.assertEqual(check.evaluate(template(), head, self.TARGET)[0], check.FAIL)

    def test_stale_stamp_fails(self):
        status, _, reasons = check.evaluate(template(), template(), self.TARGET, declared=(50100, 50000))
        self.assertEqual(status, check.FAIL)
        self.assertIn("regenerate the module", reasons[0])

    def test_base_without_versions_is_treated_as_unchanged(self):
        base = copy.deepcopy(template())
        del base["version"]
        del base["template"]["mappings"]["_meta"]
        status, change, _ = check.evaluate(base, template(), self.TARGET)
        self.assertEqual((status, change), (check.WARN, "none"))


if __name__ == "__main__":
    unittest.main()
