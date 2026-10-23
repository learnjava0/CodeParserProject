from src.agent.github.diff_mapper import (
    get_overlapping_functions,
    map_diff_to_functions,
    parse_unified_diff,
)


def test_parse_single_hunk_diff():
    patch = """@@ -1,4 +1,5 @@
 def hello():
-    print("old")
+    print("new 1")
+    print("new 2")
     return True
"""
    changed_lines, line_to_pos = parse_unified_diff(patch)
    # Line 2 and Line 3 are added
    assert changed_lines == [2, 3]
    # Check diff position mapping: @@ is 1, def hello() is 2, -print("old") is 3, +new 1 is 4, +new 2 is 5
    assert line_to_pos[2] == 4
    assert line_to_pos[3] == 5


def test_parse_multi_hunk_diff():
    patch = """@@ -5,3 +5,4 @@
 def func_one():
+    x = 1
     return x
@@ -20,3 +21,4 @@
 def func_two():
+    y = 2
     return y
"""
    changed_lines, line_to_pos = parse_unified_diff(patch)
    assert 6 in changed_lines
    assert 22 in changed_lines
    # @@ is 1, def func_one() is 2, +x=1 is 3
    assert line_to_pos[6] == 3
    # @@ is 5, def func_two() is 6, +y=2 is 7
    assert line_to_pos[22] == 7


def test_map_diff_to_overlapping_functions():
    functions = [
        {"name": "f1", "start_line": 5, "end_line": 10, "code": "def f1(): pass"},
        {"name": "f2", "start_line": 20, "end_line": 30, "code": "def f2(): pass"},
    ]
    changed_lines = [7, 8, 40]
    line_to_pos = {7: 3, 8: 4, 40: 10}

    res = map_diff_to_functions(changed_lines, functions, line_to_pos)
    assert len(res.overlapping_functions) == 1
    assert res.overlapping_functions[0]["name"] == "f1"
    assert res.overlapping_functions[0]["modified_lines"] == [7, 8]
    assert res.overlapping_functions[0]["diff_positions"] == [3, 4]
    # Line 40 is outside all functions
    assert res.unscoped_lines == [40]


def test_empty_diff():
    changed_lines, line_to_pos = parse_unified_diff("")
    assert changed_lines == []
    assert line_to_pos == {}


def test_backward_compatible_get_overlapping_functions():
    functions = [
        {"name": "foo", "start_line": 1, "end_line": 5, "code": "..."},
        {"name": "bar", "start_line": 10, "end_line": 15, "code": "..."},
    ]
    overlap = get_overlapping_functions([3], functions)
    assert len(overlap) == 1
    assert overlap[0]["name"] == "foo"
