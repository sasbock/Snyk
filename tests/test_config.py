import os
import unittest

from snyk_generate_cra_sbom_vex import cli, config
from snyk_generate_cra_sbom_vex.errors import ConfigError


class BuildConfigTests(unittest.TestCase):
    def setUp(self):
        self._env_token = os.environ.pop("SNYK_TOKEN", None)

    def tearDown(self):
        if self._env_token is not None:
            os.environ["SNYK_TOKEN"] = self._env_token
        else:
            os.environ.pop("SNYK_TOKEN", None)

    def test_token_required(self):
        args = cli.parse_args(["--org", "A"])
        with self.assertRaises(ConfigError):
            config.build_config(args)

    def test_token_from_flag(self):
        args = cli.parse_args(["--org", "A", "--token", "flag-token"])
        run_config = config.build_config(args)
        self.assertEqual(run_config.token, "flag-token")

    def test_token_from_env(self):
        os.environ["SNYK_TOKEN"] = "env-token"
        args = cli.parse_args(["--org", "A"])
        run_config = config.build_config(args)
        self.assertEqual(run_config.token, "env-token")

    def test_token_flag_takes_precedence_over_env(self):
        os.environ["SNYK_TOKEN"] = "env-token"
        args = cli.parse_args(["--org", "A", "--token", "flag-token"])
        run_config = config.build_config(args)
        self.assertEqual(run_config.token, "flag-token")

    def test_generate_vex_default_true(self):
        args = cli.parse_args(["--org", "A", "--token", "t"])
        run_config = config.build_config(args)
        self.assertTrue(run_config.generate_vex)
        self.assertIsNone(run_config.vex_skip_reason)

    def test_no_vex_flag_disables_vex(self):
        args = cli.parse_args(["--org", "A", "--token", "t", "--no-vex"])
        run_config = config.build_config(args)
        self.assertFalse(run_config.generate_vex)
        self.assertIsNone(run_config.vex_skip_reason)

    def test_spdx_format_disables_vex_with_reason(self):
        args = cli.parse_args(
            ["--org", "A", "--token", "t", "--sbom-format", "spdx2.3+json"]
        )
        run_config = config.build_config(args)
        self.assertFalse(run_config.generate_vex)
        self.assertIsNotNone(run_config.vex_skip_reason)

    def test_sources_deduplicated_shape(self):
        args = cli.parse_args(
            ["--org", "A", "--project", "D", "--token", "t"]
        )
        run_config = config.build_config(args)
        self.assertEqual(run_config.sources.orgs, ("A",))
        self.assertEqual(run_config.sources.projects, ("D",))
        self.assertEqual(run_config.sources.count(), 2)


if __name__ == "__main__":
    unittest.main()
