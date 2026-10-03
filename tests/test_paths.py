"""Filesystem policy: allowed roots, denied globs, never-paths, symlinks, walks."""
from __future__ import annotations

import os

from helpers import SanchoTestCase

from sancho import config, paths


class PathsTest(SanchoTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.proj = os.path.join(self.home, "Projects", "app")
        self.make_file("home/Projects/app/main.py", "print(1)")
        self.make_file("home/Projects/app/.env", "TOKEN=x")
        self.make_file("home/.ssh/id_rsa", "key")
        self.make_file("home/.aws/credentials", "key")
        self.make_file("home/Private/notes.txt", "private")

    # ── allowed roots ─────────────────────────────────────────────────────
    def test_default_roots(self):
        self.assertTrue(paths.judge(os.path.join(self.proj, "main.py"))[0])
        self.assertTrue(paths.judge("~/Documents/new.txt")[0])
        self.assertFalse(paths.judge("~/Private/notes.txt")[0])
        self.assertFalse(paths.judge("/etc/passwd")[0])
        self.assertFalse(paths.judge(self.home)[0])

    def test_relative_paths_resolve_against_cwd(self):
        self.assertTrue(paths.judge("main.py", self.proj)[0])
        self.assertFalse(paths.judge("../../Private/notes.txt", self.proj)[0])
        self.assertFalse(paths.judge("../../../../../../etc/passwd", self.proj)[0])

    def test_configured_roots_replace_the_defaults(self):
        self.write_config({"gate": {"allowed_roots": ["~/Private"]}})
        self.assertTrue(paths.judge("~/Private/notes.txt")[0])
        self.assertFalse(paths.judge(os.path.join(self.proj, "main.py"))[0])

    def test_a_sibling_with_a_common_prefix_is_outside(self):
        os.makedirs(os.path.join(self.home, "Projects-evil"))
        self.assertFalse(paths.judge("~/Projects-evil/x")[0])

    def test_scratch_roots_are_reachable(self):
        scratch = os.path.join(self.tmp, "scratch")
        self.write_config({"gate": {"scratch_roots": [scratch]}})
        self.assertTrue(paths.is_scratch(os.path.join(scratch, "a.txt")))
        self.assertTrue(paths.judge(os.path.join(scratch, "a.txt"))[0])
        self.assertFalse(paths.is_scratch(os.path.join(self.proj, "main.py")))

    # ── denied globs ──────────────────────────────────────────────────────
    def test_default_denied_globs(self):
        for p in ["~/Projects/app/.env", "~/Projects/app/.env.local", "~/Projects/x/.envrc",
                  "~/.ssh/id_rsa", "~/.ssh", "~/.aws/credentials", "~/.config/gh/hosts.yml",
                  "~/Library/Keychains/login.keychain-db", "~/Projects/x/credentials",
                  "~/Projects/x/server.pem", "~/Projects/x/tls.key", "~/Documents/id_rsa.bak",
                  "~/.claude.json", "~/.claude/settings.json"]:
            with self.subTest(p=p):
                self.assertTrue(paths.is_denied(p), p)

    def test_denied_wins_over_allowed(self):
        ok, why = paths.judge(os.path.join(self.proj, ".env"))
        self.assertFalse(ok)
        self.assertIn(".env", why)

    def test_denied_ignores_case(self):
        self.assertTrue(paths.is_denied("~/.SSH/id_rsa"))
        self.assertTrue(paths.is_denied("~/Projects/app/.ENV"))

    def test_extra_denied_adds_to_the_defaults(self):
        self.write_config({"gate": {"extra_denied": ["~/Projects/app/secrets/**", "*.sqlite"]}})
        self.assertTrue(paths.is_denied("~/Projects/app/secrets"))
        self.assertTrue(paths.is_denied("~/Projects/app/secrets/a/b.txt"))
        self.assertTrue(paths.is_denied("~/Documents/db.sqlite"))
        self.assertTrue(paths.is_denied("~/Projects/app/.env"))
        self.assertFalse(paths.is_denied("~/Projects/app/main.py"))

    def test_bare_folder_and_contents_both_match(self):
        self.write_config({"gate": {"extra_denied": ["~/Documents/tax"]}})
        self.assertTrue(paths.is_denied("~/Documents/tax"))
        self.assertTrue(paths.is_denied("~/Documents/tax/2024.pdf"))
        self.assertFalse(paths.is_denied("~/Documents/taxes.txt"))

    # ── never-paths ───────────────────────────────────────────────────────
    def test_sancho_itself_is_never_reachable(self):
        for p in [config.state_dir(), os.path.join(config.state_dir(), "pending", "x.json"),
                  config.REPO_DIR, os.path.join(config.REPO_DIR, "sancho", "tiers.py"),
                  os.path.join(config.REPO_DIR, ".env"), config.config_path(),
                  config.env_file_path()]:
            with self.subTest(p=p):
                self.assertTrue(paths.is_denied(p))

    def test_never_paths_hold_even_inside_an_allowed_root(self):
        state = os.path.join(self.home, "Projects", "sancho-state")
        self.write_config({"sancho": {"state_dir": state},
                           "gate": {"denied_globs": [], "allowed_roots": ["~/Projects"]}})
        # write_config forces the helper's own state dir; point it back
        cfg = config.load()
        cfg["sancho"]["state_dir"] = state
        self.assertTrue(paths.is_denied(os.path.join(state, "threads.json")))
        self.assertTrue(paths.is_denied("~/.claude/settings.json"))
        self.assertTrue(paths.is_denied("~/.claude.json"))

    def test_emptying_denied_globs_keeps_the_unconditional_list(self):
        self.write_config({"gate": {"denied_globs": []}})
        self.assertFalse(paths.is_denied("~/Projects/app/.env"))
        self.assertTrue(paths.is_denied("~/.claude/settings.json"))
        self.assertTrue(paths.is_denied(os.path.join(config.REPO_DIR, "config.json")))

    # ── symlinks ──────────────────────────────────────────────────────────
    def test_symlink_smuggling_into_ssh_is_denied(self):
        link = os.path.join(self.proj, "keys")
        os.symlink(os.path.join(self.home, ".ssh"), link)
        self.make_file("home/.ssh/config", "Host x")
        ok, why = paths.judge(os.path.join(link, "config"))
        self.assertFalse(ok)
        self.assertIn(".ssh", why)

    def test_symlink_out_of_the_roots_is_outside(self):
        link = os.path.join(self.proj, "private")
        os.symlink(os.path.join(self.home, "Private"), link)
        self.assertFalse(paths.judge(os.path.join(link, "notes.txt"))[0])

    def test_a_link_named_like_a_secret_is_denied_by_name(self):
        link = os.path.join(self.proj, "prod.pem")
        os.symlink(os.path.join(self.proj, "main.py"), link)
        self.assertTrue(paths.is_denied(link))

    # ── recursive reach ───────────────────────────────────────────────────
    def test_contains_never_sees_protected_folders_below(self):
        self.assertIsNotNone(paths.contains_never(self.home))
        self.assertIsNone(paths.contains_never(self.proj))

    def test_scan_finds_a_floating_secret(self):
        status, what = paths.scan_tree(self.proj)
        self.assertEqual(status, "denied")
        self.assertTrue(what.endswith(".env"))

    def test_scan_honours_exclusions_and_hidden(self):
        self.assertEqual(paths.scan_tree(self.proj, exclude=(".env",))[0], "clean")
        self.assertEqual(paths.scan_tree(self.proj, include_hidden=False)[0], "clean")
        self.assertEqual(paths.scan_tree(self.proj, only=("*.py",))[0], "clean")

    def test_scan_flags_a_link_that_leaves_the_roots(self):
        os.remove(os.path.join(self.proj, ".env"))
        self.assertEqual(paths.scan_tree(self.proj)[0], "clean")
        os.symlink(os.path.join(self.home, "Private"), os.path.join(self.proj, "p"))
        self.assertEqual(paths.scan_tree(self.proj)[0], "denied")

    def test_scan_gives_up_on_large_trees(self):
        for i in range(30):
            self.make_file(f"home/Documents/big/f{i}.txt")
        status, _ = paths.scan_tree("~/Documents/big", limit=10)
        self.assertEqual(status, "too_big")

    # ── review regressions ────────────────────────────────────────────────
    def test_project_claude_config_is_unconditional(self):
        self.write_config({"gate": {"denied_globs": [], "extra_denied": []}})
        for p in ["~/Projects/app/.claude", "~/Projects/app/.claude/settings.json",
                  "~/Projects/app/sub/.mcp.json", "~/Documents/.CLAUDE/hooks/x"]:
            with self.subTest(p=p):
                self.assertTrue(paths.is_denied(p))
        self.assertFalse(paths.is_denied("~/Projects/app/CLAUDE.md"))

    def test_include_globs_match_by_path_and_last_component(self):
        for glob in ("**/.env", "*/.env", ".ENV", "*"):
            with self.subTest(glob=glob):
                self.assertEqual(paths.scan_tree(self.proj, only=(glob,))[0], "denied")
        self.assertEqual(paths.scan_tree(self.proj, only=("*.py", "src/*.md"))[0], "clean")
        self.assertIsNone(paths.include_matcher(["*.{py,env}"]))
