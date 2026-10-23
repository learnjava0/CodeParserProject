from src.agent.parser.ast_parser import extract_functions, parse_source


def test_normal_function():
    code = """def calculate_total(price, tax):
    return price + (price * tax)
"""
    res = parse_source(code)
    assert not res.has_syntax_errors
    assert len(res.functions) == 1
    func = res.functions[0]
    assert func["name"] == "calculate_total"
    assert func["start_line"] == 1
    assert func["end_line"] == 2
    assert not func["is_async"]
    assert func["class_name"] is None


def test_async_function():
    code = """async def fetch_user_data(user_id: int):
    data = await db.query(user_id)
    return data
"""
    res = parse_source(code)
    assert not res.has_syntax_errors
    assert len(res.functions) == 1
    func = res.functions[0]
    assert func["name"] == "fetch_user_data"
    assert func["is_async"] is True


def test_nested_function():
    code = """def outer_function(x):
    def inner_helper(y):
        return y * 2
    return inner_helper(x) + 1
"""
    res = parse_source(code)
    assert not res.has_syntax_errors
    assert len(res.functions) == 2
    names = [f["name"] for f in res.functions]
    assert "outer_function" in names
    assert "inner_helper" in names

    inner = next(f for f in res.functions if f["name"] == "inner_helper")
    assert inner["parent_function"] == "outer_function"
    assert inner["qualified_name"] == "outer_function.inner_helper"


def test_class_methods():
    code = """class OrderService:
    def process_order(self, order_id):
        return True

    async def cancel_order(self, order_id):
        return False
"""
    res = parse_source(code)
    assert not res.has_syntax_errors
    assert len(res.functions) == 2

    proc = next(f for f in res.functions if f["name"] == "process_order")
    assert proc["class_name"] == "OrderService"
    assert proc["qualified_name"] == "OrderService.process_order"
    assert not proc["is_async"]

    cancel = next(f for f in res.functions if f["name"] == "cancel_order")
    assert cancel["class_name"] == "OrderService"
    assert cancel["qualified_name"] == "OrderService.cancel_order"
    assert cancel["is_async"] is True


def test_multiline_function():
    code = """def complex_query(
    user_id: int,
    session_token: str,
    include_metadata: bool = False,
) -> dict:
    result = {"id": user_id}
    return result
"""
    res = parse_source(code)
    assert not res.has_syntax_errors
    assert len(res.functions) == 1
    func = res.functions[0]
    assert func["start_line"] == 1
    assert func["end_line"] == 7


def test_invalid_syntax_detection():
    bad_code = """def broken_function(:
    x = 10
"""
    res = parse_source(bad_code)
    assert res.has_syntax_errors is True
    assert len(res.syntax_errors) > 0


def test_unicode_source():
    code = """def привет_мир(значение: str) -> str:
    # 🔒 Sécurité et vérification: üñîçødë
    return f"Привет, {значение} 🎉"
"""
    res = parse_source(code)
    assert not res.has_syntax_errors
    assert len(res.functions) == 1
    assert res.functions[0]["name"] == "привет_мир"


def test_empty_and_whitespace_source():
    assert parse_source("").functions == []
    assert parse_source("   \n\n\t  ").functions == []
    assert parse_source(b"").functions == []


def test_unsupported_language():
    res = parse_source("const x = 10;", language="javascript")
    assert res.has_syntax_errors is True
    assert "Unsupported language" in res.syntax_errors[0]


def test_extract_functions_backward_compatibility():
    code = b"def legacy(): pass"
    funcs = extract_functions(code)
    assert len(funcs) == 1
    assert funcs[0]["name"] == "legacy"
    assert funcs[0]["start_line"] == 1
    assert funcs[0]["end_line"] == 1
