"""Shell parser: segments, quoting, substitutions, redirections, heredocs, errors."""
from __future__ import annotations

import unittest

import helpers  # noqa: F401  (puts the repo on sys.path)

from sancho.shellparse import ParseError, expand_braces, parse, split


def argvs(cmd: str) -> list[list[str]]:
    return split(cmd)


class SegmentsTest(unittest.TestCase):
    def test_every_separator_splits(self):
        self.assertEqual(argvs("a 1; b 2 && c || d | e |& f & g\nh"),
                         [["a", "1"], ["b", "2"], ["c"], ["d"], ["e"], ["f"], ["g"], ["h"]])

    def test_separators_inside_quotes_do_not_split(self):
        self.assertEqual(argvs("echo 'a; b && c' \"d | e\""), [["echo", "a; b && c", "d | e"]])

    def test_subshells_and_groups(self):
        self.assertEqual(argvs("{ ls; } && (cd a; rm b)"), [["ls"], ["cd", "a"], ["rm", "b"]])

    def test_keywords_are_not_programs(self):
        self.assertEqual(argvs("if true; then rm x; fi"), [["true"], ["rm", "x"]])
        self.assertEqual(argvs("while true; do ls; done"), [["true"], ["ls"]])
        self.assertEqual(argvs("! grep x f"), [["grep", "x", "f"]])
        self.assertEqual(argvs("time -p ls"), [["ls"]])

    def test_comments_are_dropped(self):
        self.assertEqual(argvs("ls # rm -rf /"), [["ls"]])
        self.assertEqual(argvs("echo a#b"), [["echo", "a#b"]])

    def test_line_continuation(self):
        self.assertEqual(argvs("ls \\\n -la"), [["ls", "-la"]])


class QuotingTest(unittest.TestCase):
    def test_quote_removal_rebuilds_the_real_program(self):
        self.assertEqual(argvs("r\\m -rf x")[0][0], "rm")
        self.assertEqual(argvs("'r''m' x")[0][0], "rm")
        self.assertEqual(argvs('"r"m x')[0][0], "rm")

    def test_single_quotes_are_literal(self):
        p = parse("echo '$HOME $(rm -rf /)'")
        self.assertEqual(p.expansions, [])
        self.assertEqual(len(p.segments), 1)
        self.assertEqual(p.segments[0].argv, ["echo", "$HOME $(rm -rf /)"])

    def test_double_quotes_still_expand(self):
        p = parse('echo "$HOME and ${TOKEN} and $(id)"')
        self.assertEqual(p.expansions, ["HOME", "TOKEN"])
        self.assertIn(["id"], [s.argv for s in p.segments])

    def test_special_parameters_are_not_environment(self):
        p = parse("echo $? $1 $$ $@")
        self.assertEqual(p.expansions, [])
        self.assertTrue(p.segments[0].words[1].dynamic)

    def test_arithmetic_names_count_as_expansions(self):
        self.assertEqual(parse("echo $((1+2))").expansions, [])
        self.assertEqual(parse("echo $((TOKEN+0))").expansions, ["TOKEN"])

    def test_glob_and_brace_flags_only_when_unquoted(self):
        w = parse("ls *.md").segments[0].words[1]
        self.assertTrue(w.glob)
        w = parse("ls '*.md'").segments[0].words[1]
        self.assertFalse(w.glob)
        w = parse("cat ~/.{ssh,aws}/x").segments[0].words[1]
        self.assertTrue(w.brace)
        self.assertEqual(expand_braces(w), ["~/.ssh/x", "~/.aws/x"])
        w = parse("cat '{a,b}'").segments[0].words[1]
        self.assertFalse(w.brace)

    def test_brace_ranges(self):
        w = parse("echo f{1..3}").segments[0].words[1]
        self.assertEqual(expand_braces(w), ["f1", "f2", "f3"])
        w = parse("echo x{a..c}").segments[0].words[1]
        self.assertEqual(expand_braces(w), ["xa", "xb", "xc"])


class SubstitutionTest(unittest.TestCase):
    def test_nested_substitutions_become_segments(self):
        p = parse("echo $(ls $(pwd)) `date`")
        self.assertEqual(sorted(s.argv[0] for s in p.segments), ["date", "echo", "ls", "pwd"])
        depths = {s.argv[0]: s.depth for s in p.segments}
        self.assertEqual(depths, {"pwd": 2, "ls": 1, "date": 1, "echo": 0})

    def test_the_outer_word_is_marked_dynamic(self):
        seg = [s for s in parse("cat $(echo x)").segments if s.depth == 0][0]
        self.assertTrue(seg.words[1].dynamic)

    def test_process_substitution(self):
        p = parse("diff <(ls a) <(ls b)")
        self.assertEqual([s.argv for s in p.segments if s.depth == 1], [["ls", "a"], ["ls", "b"]])

    def test_backticks_inside_double_quotes(self):
        p = parse('echo "today `date`"')
        self.assertIn(["date"], [s.argv for s in p.segments])


class RedirectionTest(unittest.TestCase):
    def test_writes_reads_and_dups(self):
        seg = parse("cmd > out.txt 2>&1 < in.txt >> log 2>/dev/null").segments[0]
        self.assertEqual(seg.argv, ["cmd"])
        self.assertEqual([w.text for w in seg.targets("write")], ["out.txt", "log"])
        self.assertEqual([w.text for w in seg.targets("read")], ["in.txt"])
        kinds = [r.kind for r in seg.redirects]
        self.assertEqual(kinds, ["write", "dup", "read", "write", "write"])

    def test_attached_and_combined_forms(self):
        seg = parse("echo x>f &>g >|h").segments[0]
        self.assertEqual([w.text for w in seg.targets("write")], ["f", "g", "h"])

    def test_a_redirection_alone_is_a_segment(self):
        seg = parse("> truncate.me").segments[0]
        self.assertEqual(seg.argv, [])
        self.assertEqual([w.text for w in seg.targets("write")], ["truncate.me"])

    def test_missing_target_is_an_error(self):
        with self.assertRaises(ParseError):
            parse("ls >")


class HeredocTest(unittest.TestCase):
    def test_quoted_body_is_data(self):
        p = parse("cat <<'EOF' > notes.txt\nrm -rf ~ ; $HOME\n(it's fine\nEOF\nls")
        self.assertEqual([s.argv for s in p.segments], [["cat"], ["ls"]])
        self.assertEqual(p.expansions, [])
        self.assertEqual(p.segments[0].heredocs[0].body, "rm -rf ~ ; $HOME\n(it's fine")
        self.assertEqual([w.text for w in p.segments[0].targets("write")], ["notes.txt"])

    def test_unquoted_body_still_expands(self):
        p = parse("cat <<EOF\nuser $USER and $(whoami)\nEOF")
        self.assertEqual(p.expansions, ["USER"])
        self.assertIn(["whoami"], [s.argv for s in p.segments])

    def test_tab_stripping_form(self):
        p = parse("cat <<-EOF\n\tbody\n\tEOF\necho done")
        self.assertEqual(p.segments[0].heredocs[0].body, "body")
        self.assertEqual(p.segments[1].argv, ["echo", "done"])

    def test_commit_message_through_a_heredoc(self):
        cmd = "git commit -m \"$(cat <<'EOF'\nFix the parser (it's ok)\nEOF\n)\""
        p = parse(cmd)
        self.assertEqual(sorted(s.argv[0] for s in p.segments), ["cat", "git"])
        self.assertEqual(p.expansions, [])

    def test_missing_terminator_is_an_error(self):
        with self.assertRaises(ParseError):
            parse("cat <<EOF\nno end")


class AssignmentTest(unittest.TestCase):
    def test_prefix_assignments_are_separated(self):
        seg = parse("A=1 B='x y' env").segments[0]
        self.assertEqual([w.text for w in seg.assignments], ["A=1", "B=x y"])
        self.assertEqual(seg.argv, ["env"])

    def test_bare_assignment(self):
        seg = parse("X=1").segments[0]
        self.assertEqual(seg.argv, [])
        self.assertEqual(len(seg.assignments), 1)

    def test_assignment_after_the_program_is_an_argument(self):
        self.assertEqual(argvs("make X=1"), [["make", "X=1"]])


class ErrorsTest(unittest.TestCase):
    def test_unbalanced_input_raises(self):
        for bad in ["echo 'x", 'echo "x', "echo $(ls", "echo `x", "echo ${X",
                    "echo $'\\x72m'", "echo \\"]:
            with self.subTest(bad=bad), self.assertRaises(ParseError):
                parse(bad)

    def test_ansi_c_string_without_escapes_is_fine(self):
        self.assertEqual(argvs("echo $'plain'"), [["echo", "plain"]])

    def test_non_string(self):
        with self.assertRaises(ParseError):
            parse(None)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
