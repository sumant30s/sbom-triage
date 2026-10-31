from pathlib import Path

from streamlit.testing.v1 import AppTest

APP = Path(__file__).parents[1] / "app.py"


def test_dashboard_demo_filters_and_empty_state():
    at = AppTest.from_file(str(APP), default_timeout=30).run()
    assert not at.exception
    at.sidebar.button[0].click().run()
    assert not at.exception
    assert at.metric[1].value == "4"
    assert any("synthetic" in w.value for w in at.warning)
    at.multiselect[0].set_value(["P0"]).run()
    assert not at.exception and len(at.dataframe[0].value) == 1
    at.text_input[0].set_value("impossible-match").run()
    assert not at.exception
    assert any("No findings" in x.value for x in at.info)
