"""Exercise deployment control flow with a shell function replacing Docker.

No daemon, network, application import, or hardware operation is performed.
Only files in a temporary directory are written.
"""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
GIT_BASH = Path(r"C:\Program Files\Git\bin\bash.exe")
BASH = str(GIT_BASH) if GIT_BASH.exists() else shutil.which("bash")
HARNESS = r'''
docker() {
  printf '%s\n' "$*" >> "$AOCT_TEST_LOG"
  case "$AOCT_TEST_FAILURE:$*" in
    config:*" config --quiet") return 41 ;;
    pull:*" pull") return 42 ;;
    up:*" up "*) return 43 ;;
  esac
}
export -f docker
bash "$@"
'''


@unittest.skipUnless(BASH, "Bash is required for isolated deployment tests")
class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.script = self.directory / "start.sh"
        shutil.copyfile(ROOT / "deploy" / "start.sh", self.script)
        self.log = self.directory / "commands.txt"

    def run_start(self, *arguments, failure=""):
        env = dict(os.environ)
        env.update(AOCT_TEST_LOG=self.log.as_posix(), AOCT_TEST_FAILURE=failure)
        result = subprocess.run(
            [BASH, "-c", HARNESS, "deployment-test", self.script.as_posix(), *arguments],
            cwd=ROOT, env=env, text=True, capture_output=True, timeout=15,
        )
        commands = self.log.read_text().splitlines() if self.log.exists() else []
        return result, commands

    def test_default_start_does_not_pull_or_build(self):
        result, commands = self.run_start()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(commands), 3)
        self.assertTrue(commands[0].endswith("config --quiet"))
        self.assertTrue(commands[1].endswith("up -d --pull never --no-build"))
        self.assertTrue(commands[2].endswith("images aircraft_ops_tool"))
        self.assertTrue((self.directory / "docker-compose.override.yml").exists())
        self.assertEqual(list(self.directory.glob("docker-compose.override.yml.*")), [])

    def test_explicit_update_pulls_before_start(self):
        result, commands = self.run_start("--update")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(commands[1].endswith(" pull"))
        self.assertTrue(commands[2].endswith("up -d --pull never --no-build"))

    def test_pull_failure_does_not_restart_running_service(self):
        result, commands = self.run_start("--update", failure="pull")
        self.assertEqual(result.returncode, 42)
        self.assertEqual(len(commands), 2)
        self.assertFalse(any(" up " in command for command in commands))

    def test_invalid_config_does_not_pull_or_start(self):
        result, commands = self.run_start("--update", failure="config")
        self.assertEqual(result.returncode, 41)
        self.assertEqual(len(commands), 1)

    def test_missing_cached_image_is_a_start_failure(self):
        result, commands = self.run_start(failure="up")
        self.assertEqual(result.returncode, 43)
        self.assertEqual(len(commands), 2)
        self.assertFalse(any(command.endswith(" pull") for command in commands))

    def test_unknown_option_has_no_side_effects(self):
        result, commands = self.run_start("--unknown")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(commands, [])
        self.assertFalse((self.directory / "docker-compose.override.yml").exists())

    def test_extra_arguments_have_no_side_effects(self):
        result, commands = self.run_start("--update", "extra")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(commands, [])


if __name__ == "__main__":
    unittest.main()
