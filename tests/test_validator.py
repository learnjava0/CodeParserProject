from src.agent.patcher.patch_validator import validate_patch

def test_invalid_syntax_rejected():
    # Missing closing parenthesis creates a syntax error
    bad_code = "def foo():\n    print('hello'"
    assert validate_patch(bad_code) is False

def test_valid_syntax_passed():
    # Valid Python syntax
    good_code = "def foo():\n    print('hello')\n"
    # Assuming semgrep finds nothing in this simple print statement
    assert validate_patch(good_code) is True
