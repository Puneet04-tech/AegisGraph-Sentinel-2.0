"""
Test suite for UX enhancement: Unsaved Content Warning (#1769)
This test verifies that the JavaScript protection script is correctly injected into the Streamlit application.
"""
from pathlib import Path

def test_app_contains_unsaved_content_warning_script():
    """
    Verify that the app.py contains the JavaScript snippet for issue #1769.
    """
    app_path = Path("app.py")
    assert app_path.exists(), "app.py does not exist"
    
    source = app_path.read_text(encoding="utf-8")
    
    # Check for core components of the script
    assert "UX Enhancement: Unsaved Content Warning (#1769)" in source
    assert "window.addEventListener('beforeunload'" in source
    assert "isDirty = true" in source
    assert "window.confirm(\"You have entered data that will be lost if you navigate away. Continue?\")" in source
    
    # Check for buttons that reset the dirty flag
    assert "Check" in source
    assert "Submit" in source
    assert "Process" in source
    assert "Score" in source
    assert "Analyze" in source
    assert "Seal" in source

def test_script_is_injected_after_style_tag():
    """
    Verify the script is correctly placed after the CSS block.
    """
    source = Path("app.py").read_text(encoding="utf-8")
    assert "</style>" in source
    assert "<script>" in source
    
    # The script should come after the style tag
    style_end = source.find("</style>")
    script_start = source.find("<script>", style_end)
    assert script_start > style_end, "Script should be placed after the </style> tag"
