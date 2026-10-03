"""Router: which folders count as projects, how names resolve, sticky choice."""
from __future__ import annotations

import os

from helpers import SanchoTestCase

from sancho import projects


class ProjectsTest(SanchoTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.root = os.path.join(self.home, "Projects")
        self.other = os.path.join(self.home, "Work")
        for name, marker in (("alpha-site", "README.md"), ("beta_tool", "CLAUDE.md"),
                             ("beta-docs", "STATUS.md"), ("gamma", "README.md"),
                             ("private-notes", "README.md")):
            self.make_file(os.path.join("home", "Projects", name, marker))
        os.makedirs(os.path.join(self.root, "no-marker"))
        self.make_file(os.path.join("home", "Projects", "loose-file.md"))
        self.make_file(os.path.join("home", "Projects", ".hidden", "README.md"))
        self.make_file(os.path.join("home", "Work", "delta", "README.md"))
        self.make_file(os.path.join("home", "Work", "gamma", "README.md"))

    def test_default_root_and_markers(self):
        self.assertEqual(sorted(projects.list_projects()),
                         ["alpha-site", "beta-docs", "beta_tool", "gamma", "private-notes"])

    def test_several_roots_first_one_wins(self):
        self.write_config({"projects": {"roots": ["~/Projects", "~/Work"]}})
        found = projects.list_projects()
        self.assertIn("delta", found)
        self.assertEqual(found["gamma"], os.path.join(self.root, "gamma"))

    def test_custom_markers(self):
        self.write_config({"projects": {"markers": ["STATUS.md"]}})
        self.assertEqual(list(projects.list_projects()), ["beta-docs"])

    def test_exact_name_with_any_separator(self):
        self.assertEqual(projects.resolve("Alpha Site")[0], os.path.join(self.root, "alpha-site"))
        self.assertEqual(projects.resolve("beta tool")[0], os.path.join(self.root, "beta_tool"))

    def test_unique_prefix_and_substring(self):
        self.assertEqual(projects.resolve("alp")[0], os.path.join(self.root, "alpha-site"))
        self.assertEqual(projects.resolve("docs")[0], os.path.join(self.root, "beta-docs"))

    def test_ambiguous_name_asks(self):
        path, candidates = projects.resolve("beta")
        self.assertIsNone(path)
        self.assertEqual(candidates, ["beta-docs", "beta_tool"])

    def test_typo_is_suggested_never_taken(self):
        path, candidates = projects.resolve("gamna")
        self.assertIsNone(path)
        self.assertEqual(candidates, ["gamma"])

    def test_unknown_name(self):
        self.assertEqual(projects.resolve("zzz"), (None, []))
        self.assertEqual(projects.resolve(""), (None, []))

    def test_folders_without_marker_are_not_projects(self):
        self.assertEqual(projects.resolve("no-marker"), (None, []))

    def test_excluded_projects_are_invisible(self):
        self.write_config({"projects": {"exclude": ["Private Notes"]}})
        self.assertNotIn("private-notes", projects.list_projects())
        self.assertEqual(projects.resolve("private-notes"), (None, []))
        self.assertTrue(projects.is_excluded("private_notes"))

    def test_name_followed_by_a_question(self):
        path, rest, _ = projects.resolve_with_rest("alpha site what changed today?")
        self.assertEqual(path, os.path.join(self.root, "alpha-site"))
        self.assertEqual(rest, "what changed today?")
        self.assertEqual(projects.resolve_with_rest("beta"), (None, "", ["beta-docs", "beta_tool"]))

    def test_sticky_choice_per_chat(self):
        self.assertIsNone(projects.current(1))
        projects.set_current(1, os.path.join(self.root, "gamma"))
        projects.set_current(2, os.path.join(self.root, "alpha-site"))
        self.assertEqual(projects.current(1), os.path.join(self.root, "gamma"))
        self.assertEqual(projects.current("2"), os.path.join(self.root, "alpha-site"))

    def test_sticky_choice_of_a_deleted_folder_is_forgotten(self):
        path = os.path.join(self.root, "gamma")
        projects.set_current(1, path)
        os.remove(os.path.join(path, "README.md"))
        os.rmdir(path)
        self.assertIsNone(projects.current(1))
