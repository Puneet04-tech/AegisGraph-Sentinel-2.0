import re

def refactor():
    with open('src/api/main.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Define the keystroke sync function to insert
    keystroke_helper = """
def _analyze_keystrokes_sync(biometrics: dict) -> bool:
    import numpy as np
    behavioral_stress_detected = False
    try:
        hold_times = biometrics.get('hold_times', [])
        flight_times = biometrics.get('flight_times', [])
        
        if hold_times and len(hold_times) > 1:
            hold_times_arr = np.array(hold_times)
            hold_cv = np.std(hold_times_arr) / np.mean(hold_times_arr)
            if hold_cv > 0.30:
                behavioral_stress_detected = True
        
        if flight_times and len(flight_times) > 1:
            flight_times_arr = np.array(flight_times)
            flight_cv = np.std(flight_times_arr) / np.mean(flight_times_arr)
            if flight_cv > 0.35:
                behavioral_stress_detected = True
    except Exception:
        pass
    return behavioral_stress_detected

"""
    
    # Insert helper before check_transaction
    content = content.replace(
        '@app.post(\n    "/api/v1/fraud/check",',
        keystroke_helper + '@app.post(\n    "/api/v1/fraud/check",'
    )

    # Replace the inline numpy logic in check_transaction
    old_inline = """            # Innovation 1: Simple keystroke stress detection
            if INNOVATIONS_AVAILABLE:
                try:
                    # Detect stress via typing variance, not absolute timing
                    hold_times = biometrics['hold_times']
                    flight_times = biometrics['flight_times']
                    
                    if hold_times and len(hold_times) > 1:
                        # Calculate coefficient of variation (std/mean)
                        hold_times_arr = np.array(hold_times)
                        hold_cv = np.std(hold_times_arr) / np.mean(hold_times_arr)
                        
                        # High variance (CV > 0.30) indicates stress/coercion
                        if hold_cv > 0.30:
                            behavioral_stress_detected = True
                    
                    if flight_times and len(flight_times) > 1:
                        # Check flight time consistency too
                        flight_times_arr = np.array(flight_times)
                        flight_cv = np.std(flight_times_arr) / np.mean(flight_times_arr)
                        if flight_cv > 0.35:
                            behavioral_stress_detected = True
                            
                except Exception as e:
                    _api_logger.warning(
                        f"Keystroke analysis failed: {e}",
                        event_type="keystroke_analysis_error",
                    )"""
                    
    new_inline = """            # Innovation 1: Simple keystroke stress detection
            if INNOVATIONS_AVAILABLE:
                try:
                    behavioral_stress_detected = await asyncio.to_thread(_analyze_keystrokes_sync, biometrics)
                except Exception as e:
                    _api_logger.warning(
                        f"Keystroke analysis failed: {e}",
                        event_type="keystroke_analysis_error",
                    )"""
                    
    content = content.replace(old_inline, new_inline)

    # Replace `loop.run_in_executor(None, partial(func, args...))` with `asyncio.to_thread(func, args...)`
    # We will use regex to find await loop.run_in_executor(\s*None,\s*partial(\s*([^\,]+),\s*(.*?)\s*)\s*)
    # Because of nested parentheses in kwargs, a simple regex might fail. 
    # Let's do it with a careful regex or literal replacements since there are only about 11 instances.
    
    content = re.sub(
        r'await loop\.run_in_executor\(\s*None,\s*partial\(\s*([\w\._]+),\s*(.*?)\s*\),\s*\)',
        r'await asyncio.to_thread(\1, \2)',
        content,
        flags=re.DOTALL
    )

    with open('src/api/main.py', 'w', encoding='utf-8') as f:
        f.write(content)
        
if __name__ == '__main__':
    refactor()
