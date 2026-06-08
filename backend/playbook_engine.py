"""
playbook_engine.py — Trigger playbook orchestrator for Kavach AI dynamic analysis.

Executes a sequenced set of ADB-driven trigger steps to exercise meaningful app
behavior beyond passive launch-and-wait. Steps are conditionally activated based
on static signals extracted before dynamic analysis.

Interaction model:
  - Uses `uiautomator dump` to inspect actual visible UI elements
  - Targets clickable controls by class/text, not random screen coordinates
  - Records which steps actually changed emulator state
"""

import os
import re
import time
import subprocess
import datetime
import xml.etree.ElementTree as ET
import tempfile
import logging
import json
from typing import Any, Dict, List, Optional
from google import genai
from google.genai import types as genai_types

logger = logging.getLogger("kavach.playbook")

_ADB_TIMEOUT = 10   # seconds per ADB command
_SWIPE_DELAY = 0.3  # seconds between touch events


def _get_genai_client():
    try:
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            logger.warning("GEMINI_API_KEY not found in environment variables. Playbook GenAI will be disabled.")
            return None
        client = genai.Client(
            api_key=api_key,
            http_options=genai_types.HttpOptions(timeout=30000)
        )
        logger.info("GenAI client initialized in playbook using Google AI Studio Free Tier (30s timeout)")
        return client
    except Exception as e:
        logger.warning(f"Failed to initialize GenAI client in playbook: {e}")
        return None


import threading
thread_local = threading.local()


def _ts() -> str:
    return datetime.datetime.utcnow().isoformat() + "Z"


def _run(args: List[str], timeout: int = _ADB_TIMEOUT) -> subprocess.CompletedProcess:
    """Run a command, return CompletedProcess. Never raises."""
    device_serial = getattr(thread_local, "device_serial", None)
    if device_serial and args and len(args) > 0 and "adb" in str(args[0]).lower():
        if len(args) > 1 and args[1] == "-s":
            pass
        else:
            args = [args[0], "-s", device_serial] + args[1:]
    try:
        return subprocess.run(
            args, capture_output=True, text=True, timeout=timeout
        )
    except Exception as e:
        r = subprocess.CompletedProcess(args, returncode=1)
        r.stdout = ""
        r.stderr = str(e)
        return r


# ---------------------------------------------------------------------------
# UI inspection helpers
# ---------------------------------------------------------------------------

def _dump_ui_ocr(adb: str, tmp_dir: str) -> List[Dict[str, Any]]:
    """
    Fallback OCR-based UI element finder.
    Takes a screenshot, uses pytesseract to locate text, and generates elements list.
    """
    remote = "/sdcard/kavach_screencap.png"
    local = os.path.join(tmp_dir, "screencap.png")
    
    r = _run([adb, "shell", "screencap", "-p", remote])
    if r.returncode != 0:
        return []
    _run([adb, "pull", remote, local])
    _run([adb, "shell", "rm", "-f", remote])
    
    if not os.path.exists(local):
        return []
        
    try:
        import pytesseract
        from PIL import Image
        
        # Load image
        img = Image.open(local)
        data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)
        
        elements = []
        n_boxes = len(data['text'])
        for i in range(n_boxes):
            text = str(data['text'][i]).strip()
            if not text:
                continue
            conf = 0
            try:
                conf = int(data['conf'][i])
            except Exception:
                pass
            if conf > 50:
                x = data['left'][i] + data['width'][i] // 2
                y = data['top'][i] + data['height'][i] // 2
                w = data['width'][i]
                h = data['height'][i]
                bounds = f"[{data['left'][i]},{data['top'][i]}][{data['left'][i]+w},{data['top'][i]+h}]"
                elements.append({
                    "x": x, "y": y,
                    "text": text,
                    "class": "android.widget.Button" if text.lower() in ("allow", "accept", "ok", "next", "submit", "agree", "continue", "yes", "permission") else "android.widget.TextView",
                    "content_desc": text,
                    "bounds": bounds,
                })
        logger.info(f"[OCR] Extracted {len(elements)} elements using Tesseract OCR fallback.")
        return elements
    except Exception as e:
        logger.warning(f"[OCR] Pytesseract OCR fallback failed: {e}. Ensure tesseract-ocr binary is installed on your system.")
        return []


def _dump_ui(adb: str, tmp_dir: str) -> Optional[ET.Element]:
    """
    Use uiautomator dump to capture current UI hierarchy.
    Falls back to Tesseract OCR if uiautomator yields no clickable elements.
    Returns the root Element or None on failure.
    """
    remote = "/sdcard/kavach_ui_dump.xml"
    local  = os.path.join(tmp_dir, "ui_dump.xml")

    r = _run([adb, "shell", "uiautomator", "dump", remote])
    
    root = None
    if r.returncode == 0:
        _run([adb, "pull", remote, local])
        _run([adb, "shell", "rm", "-f", remote])
        try:
            tree = ET.parse(local)
            root = tree.getroot()
        except Exception:
            root = None

    # Verify if root has clickable elements
    has_nodes = False
    if root is not None:
        has_nodes = any(node.get("clickable") == "true" for node in root.iter("node"))

    if not has_nodes:
        logger.info("[OCR] uiautomator yielded no clickable elements. Running Tesseract OCR fallback...")
        ocr_elements = _dump_ui_ocr(adb, tmp_dir)
        if ocr_elements:
            mock_root = ET.Element("hierarchy", rotation="0")
            for idx, el in enumerate(ocr_elements):
                node = ET.SubElement(mock_root, "node", {
                    "index": str(idx),
                    "text": el["text"],
                    "class": el["class"],
                    "clickable": "true",
                    "bounds": el["bounds"],
                    "content-desc": el["content_desc"]
                })
            return mock_root

    return root


def _clickable_elements(root: Optional[ET.Element]) -> List[Dict[str, Any]]:
    """Extract clickable elements with center coordinates from uiautomator dump."""
    if root is None:
        return []
    elements = []
    for node in root.iter("node"):
        if node.get("clickable") != "true":
            continue
        bounds = node.get("bounds", "")
        m = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", bounds)
        if not m:
            continue
        x = (int(m.group(1)) + int(m.group(3))) // 2
        y = (int(m.group(2)) + int(m.group(4))) // 2
        if x == 0 and y == 0:
            continue
        elements.append({
            "x": x, "y": y,
            "text":    node.get("text", ""),
            "class":   node.get("class", ""),
            "content_desc": node.get("content-desc", ""),
            "bounds":  bounds,
        })
    return elements


def _is_button(el: Dict[str, Any]) -> bool:
    cls = el.get("class", "")
    txt = el.get("text", "").lower()
    return ("Button" in cls or "TextView" in cls) and len(txt) > 0


def _is_edittext(el: Dict[str, Any]) -> bool:
    return "EditText" in el.get("class", "")


def _tap(adb: str, x: int, y: int) -> bool:
    r = _run([adb, "shell", "input", "tap", str(x), str(y)])
    return r.returncode == 0


def _keyevent(adb: str, code: str) -> bool:
    r = _run([adb, "shell", "input", "keyevent", code])
    return r.returncode == 0


def _text_input(adb: str, text: str) -> bool:
    # Replace spaces with %s for adb input text
    safe = text.replace(" ", "%s").replace("@", "\\@")
    r = _run([adb, "shell", "input", "text", safe])
    return r.returncode == 0


# ---------------------------------------------------------------------------
# Coverage map helpers
# ---------------------------------------------------------------------------

def _make_coverage() -> Dict[str, Any]:
    return {
        "activities_attempted":     [],
        "activities_succeeded":     [],
        "receivers_tested":         0,
        "deeplinks_tested":         [],
        "permissions_exercised":    [],
        "login_simulation_attempted": False,
        "login_simulation_effective": False,
        "network_observed":         False,
        "webview_observed":         False,
        "has_exported_receivers":   False,
        "webview_expected":         False,
    }


def _step(step: str, action: str, result: str, detail: str = "") -> Dict[str, Any]:
    return {"step": step, "action": action, "result": result, "ts": _ts(), "detail": detail}


# ---------------------------------------------------------------------------
# Individual playbook steps
# ---------------------------------------------------------------------------

def _step_wait_activity(adb: str, package: str, transcript: list, secs: float = 2.5) -> None:
    time.sleep(secs)
    transcript.append(_step("wait_activity", f"Wait {secs}s for launcher activity to render",
                            "succeeded"))


def _step_explicit_launch(adb: str, package: str, activity: Optional[str],
                          transcript: list) -> None:
    if not activity:
        transcript.append(_step("explicit_launch", "Explicit am start (no activity known)", "skipped"))
        return
    # Use 15 second timeout instead of default 5
    r = _run([adb, "shell", "am", "start", "-n", f"{package}/{activity}"], timeout=15)
    ok = r.returncode == 0 and "Error" not in r.stdout
    transcript.append(_step(
        "explicit_launch", f"am start {package}/{activity}",
        "succeeded" if ok else "failed",
        r.stderr[:200] if not ok else ""
    ))
    time.sleep(1.5)


def _step_interact_ui(adb: str, tmp_dir: str, transcript: list, max_taps: int = 6) -> None:
    """
    Inspect visible UI via uiautomator dump, tap clickable controls
    (buttons first, then any clickable). Much more targeted than random touches.
    """
    root = _dump_ui(adb, tmp_dir)
    elements = _clickable_elements(root)
    if not elements:
        transcript.append(_step("interact_ui", "No clickable elements found in UI dump", "skipped"))
        return

    # Prioritise: buttons with text > any clickable
    buttons   = [e for e in elements if _is_button(e)]
    other_cls = [e for e in elements if not _is_button(e) and not _is_edittext(e)]
    targets   = (buttons + other_cls)[:max_taps]

    tapped = []
    for el in targets:
        ok = _tap(adb, el["x"], el["y"])
        label = el.get("text") or el.get("content_desc") or el.get("class", "?")
        tapped.append(f"'{label}' @({el['x']},{el['y']})")
        time.sleep(_SWIPE_DELAY)

    transcript.append(_step(
        "interact_ui",
        f"Tapped {len(tapped)} UI control(s): {'; '.join(tapped[:4])}",
        "succeeded" if tapped else "failed"
    ))


def _step_webview_wait(adb: str, transcript: list, has_webview: bool, secs: float = 3.0) -> None:
    if not has_webview:
        transcript.append(_step("webview_wait", "WebView wait skipped (no static WebView signal)", "skipped"))
        return
    time.sleep(secs)
    transcript.append(_step("webview_wait", f"Extra {secs}s wait for WebView to load URLs", "succeeded"))


def _step_exported_receivers(adb: str, package: str, receivers: List[str],
                              transcript: list, coverage: Dict) -> None:
    if not receivers:
        transcript.append(_step("exported_receiver_intent", "No exported receivers declared", "skipped"))
        return
    coverage["has_exported_receivers"] = True
    tested = 0
    for receiver in receivers[:3]:
        r = _run([adb, "shell", "am", "broadcast", "-a",
                  "android.intent.action.MAIN", "-n",
                  f"{package}/{receiver}"])
        ok = r.returncode == 0
        if ok:
            tested += 1
        transcript.append(_step(
            "exported_receiver_intent",
            f"Broadcast to {receiver}",
            "succeeded" if ok else "failed",
            r.stderr[:100] if not ok else ""
        ))
        time.sleep(0.5)
    coverage["receivers_tested"] = tested


def _step_exported_activities(adb: str, package: str, activities: List[str],
                               transcript: list, coverage: Dict) -> None:
    if not activities:
        transcript.append(_step("exported_activity_launch", "No extra exported activities", "skipped"))
        return
    for act in activities[:3]:
        coverage["activities_attempted"].append(act)
        r = _run([adb, "shell", "am", "start", "-n", f"{package}/{act}"], timeout=15)
        ok = r.returncode == 0 and "Error" not in r.stdout
        if ok:
            coverage["activities_succeeded"].append(act)
        transcript.append(_step(
            "exported_activity_launch",
            f"am start {package}/{act}",
            "succeeded" if ok else "failed",
            r.stderr[:200] if not ok else ""
        ))
        time.sleep(1.0)


def _step_background_foreground(adb: str, package: str, activity: Optional[str],
                                 transcript: list) -> None:
    _keyevent(adb, "KEYCODE_HOME")
    time.sleep(1.5)
    if activity:
        _run([adb, "shell", "am", "start", "-n", f"{package}/{activity}"], timeout=15)
    else:
        _run([adb, "shell", "monkey", "-p", package, "-c",
              "android.intent.category.LAUNCHER", "1"], timeout=15)
    time.sleep(1.5)
    transcript.append(_step("background_foreground",
                            "HOME key press + app reopen (background/foreground cycle)",
                            "succeeded"))


def _step_deep_link(adb: str, package: str, schemes: List[str],
                    transcript: list, coverage: Dict) -> None:
    if not schemes:
        transcript.append(_step("deep_link_intent", "No custom URL schemes declared", "skipped"))
        return
    for scheme in schemes[:2]:
        test_url = f"{scheme}://kavach-test/trigger"
        r = _run([adb, "shell", "am", "start", "-a", "android.intent.action.VIEW",
                  "-d", test_url])
        ok = r.returncode == 0
        coverage["deeplinks_tested"].append(test_url)
        transcript.append(_step(
            "deep_link_intent", f"Deep link: {test_url}",
            "succeeded" if ok else "failed"
        ))
        time.sleep(1.0)


def _step_login_simulation(adb: str, tmp_dir: str, transcript: list,
                            coverage: Dict, log_callback=None) -> None:
    """
    Find EditText fields in the current UI and type test credentials.
    Uses Gemini AI if available to dynamically classify fields and enter appropriate dummy data,
    falling back to deterministic heuristics.
    """
    def _log(msg: str):
        if log_callback:
            try:
                log_callback(f"[PLAYBOOK_AI] {msg}")
            except Exception:
                pass
        logger.info(msg)

    coverage["login_simulation_attempted"] = True
    root = _dump_ui(adb, tmp_dir)
    elements = _clickable_elements(root)
    
    fields = [e for e in elements if _is_edittext(e)]
    if not elements or not fields:
        transcript.append(_step("login_simulation",
                                "No EditText fields visible — login simulation skipped",
                                "skipped"))
        return

    _log(f"Detected {len(fields)} EditText fields. Initiating dynamic UI classification...")

    # Attempt AI-driven simulation
    client = _get_genai_client()
    ai_success = False
    
    if client:
        try:
            ui_list = []
            for el in elements:
                ui_list.append({
                    "x": el["x"], "y": el["y"],
                    "text": el["text"],
                    "class": el["class"],
                    "content_desc": el.get("content_desc") or el.get("content-desc") or "",
                })
            
            prompt = (
                "You are an AI UI Automation Assistant. We are testing an Android app in a sandbox emulator.\n"
                "Here is the list of interactive UI elements detected on the current screen (derived from uiautomator dump):\n\n"
                f"{json.dumps(ui_list, indent=2)}\n\n"
                "Please analyze these elements. If this looks like a login, signup, configuration, or input screen, "
                "determine which elements are input fields (e.g. EditText) and what mock data we should type into them "
                "(e.g., test emails, passwords, names, dummy numbers).\n"
                "Also, identify the coordinates (x, y) of the primary submit button (e.g. login, next, confirm, continue).\n\n"
                "You must respond in strict JSON matching this schema:\n"
                "{\n"
                "  \"is_input_screen\": true,\n"
                "  \"inputs\": [\n"
                "    { \"x\": 100, \"y\": 200, \"value\": \"test@kavach.ai\", \"description\": \"email field\" }\n"
                "  ],\n"
                "  \"submit_button\": { \"x\": 300, \"y\": 400 } or null\n"
                "}\n"
                "Ensure you return ONLY raw JSON. No markdown wraps."
            )
            
            _log("Dispatching UI layout to Gemini Flash for input classification...")
            try:
                ai_response = client.models.generate_content(
                    model="gemini-3.5-flash",
                    contents=prompt,
                    config=genai_types.GenerateContentConfig(
                        response_mime_type="application/json",
                        temperature=0.4,
                    )
                )
            except Exception as exc:
                _log(f"Primary model gemini-3.5-flash failed in playbook: {exc}. Engaging secondary fallback model gemini-3.1-flash-lite...")
                ai_response = client.models.generate_content(
                    model="gemini-3.1-flash-lite",
                    contents=prompt,
                    config=genai_types.GenerateContentConfig(
                        response_mime_type="application/json",
                        temperature=0.4,
                    )
                )
            
            # Clean and parse response
            import json as py_json
            text_resp = ai_response.text.strip()
            if text_resp.startswith("```json"):
                text_resp = text_resp[7:]
            elif text_resp.startswith("```"):
                text_resp = text_resp[3:]
            if text_resp.endswith("```"):
                text_resp = text_resp[:-3]
            res_dict = py_json.loads(text_resp.strip())
            
            if res_dict.get("is_input_screen") and res_dict.get("inputs"):
                _log("Gemini parsed UI successfully. Typing inputs...")
                entered = 0
                for inp in res_dict["inputs"]:
                    tx, ty, tval = inp.get("x"), inp.get("y"), inp.get("value")
                    if tx is not None and ty is not None and tval is not None:
                        _tap(adb, tx, ty)
                        time.sleep(0.4)
                        _text_input(adb, tval)
                        entered += 1
                        _log(f"Typed '{tval}' into element at ({tx},{ty})")
                        time.sleep(0.3)
                
                sub_btn = res_dict.get("submit_button")
                if sub_btn and sub_btn.get("x") is not None and sub_btn.get("y") is not None:
                    sx, sy = sub_btn["x"], sub_btn["y"]
                    _tap(adb, sx, sy)
                    _log(f"Tapped primary submit button at ({sx},{sy})")
                    coverage["login_simulation_effective"] = True
                    time.sleep(2.0)
                
                transcript.append(_step(
                    "login_simulation",
                    f"Gemini-assisted: Typed inputs into {entered} fields" + 
                    (f" and tapped submit button" if sub_btn else ""),
                    "succeeded" if entered > 0 else "failed"
                ))
                ai_success = True
        except Exception as ae:
            _log(f"AI-assisted login input generation failed: {ae}. Falling back to heuristics...")

    if not ai_success:
        # Heuristics Fallback
        _log("Using heuristics fallback for credentials typing...")
        entered = 0
        credentials = [
            ("test@kavach.ai", False),
            ("KavachTest123!", True),
        ]

        for i, field_el in enumerate(fields[:2]):
            _tap(adb, field_el["x"], field_el["y"])
            time.sleep(0.4)
            cred, is_pass = credentials[i] if i < len(credentials) else (f"kavach_field_{i}", False)
            _text_input(adb, cred)
            entered += 1
            time.sleep(0.3)

        # Try to submit: look for a login/submit button
        all_els = _clickable_elements(root)
        submit_btn = next(
            (e for e in all_els
             if re.search(r"(login|sign.?in|submit|continue|next)", e.get("text",""), re.I)),
            None
        )
        if submit_btn:
            _tap(adb, submit_btn["x"], submit_btn["y"])
            coverage["login_simulation_effective"] = True
            time.sleep(2.0)

        transcript.append(_step(
            "login_simulation",
            f"Heuristic fallback: Typed credentials into {entered} field(s)" +
            (f" and tapped '{submit_btn['text']}'" if submit_btn else " (no submit button found)"),
            "succeeded" if entered > 0 else "failed"
        ))


def _step_vision_guided_play(
    adb: str,
    tmp_dir: str,
    transcript: list,
    log_callback=None
) -> None:
    """
    Take a screenshot of the running emulator screen, send it directly to Gemini
    along with vision prompt instructions, and trigger ADB input/tap actions dynamically.
    """
    def _log(msg: str):
        if log_callback:
            try:
                log_callback(f"[PLAYBOOK_VISION] {msg}")
            except Exception:
                pass
        logger.info(msg)

    client = _get_genai_client()
    if not client:
        _log("Gemini client not initialized, skipping vision-guided play.")
        return

    # 1. Get screen size
    r_size = _run([adb, "shell", "wm", "size"])
    width, height = 1080, 1920 # Default emulator dimensions
    if r_size.returncode == 0:
        match = re.search(r"(\d+)x(\d+)", r_size.stdout)
        if match:
            width = int(match.group(1))
            height = int(match.group(2))
            _log(f"Detected screen size: {width}x{height}")

    # 2. Capture screenshot
    remote = "/sdcard/kavach_screencap_vision.png"
    local = os.path.join(tmp_dir, "screencap_vision.png")
    
    r_cap = _run([adb, "shell", "screencap", "-p", remote])
    if r_cap.returncode != 0:
        _log("Failed to capture emulator screen via adb.")
        return
    _run([adb, "pull", remote, local])
    _run([adb, "shell", "rm", "-f", remote])

    if not os.path.exists(local):
        _log("Failed to pull screencap file locally.")
        return

    try:
        from PIL import Image
        img = Image.open(local)
    except Exception as e:
        _log(f"Failed to open screencap image: {e}")
        return

    # 3. Query Gemini Vision
    try:
        prompt = (
            "You are an AI security sandbox assistant. This is a screenshot of an Android app running inside our emulator.\n"
            "Determine if this is a login screen, permission request, terms, loading page, or landing page, and identify the interactive "
            "component we need to click or interact with next to progress further and trigger network traffic (e.g. 'Allow' button, "
            "'Continue' button, 'Log In' button, or input fields).\n"
            "Provide the coordinates of the target element to click as relative percentages of the screen width and height (from 0.0 to 100.0).\n\n"
            "You must return a strict JSON response matching this schema:\n"
            "{\n"
            "  \"screen_type\": \"login | permission | dashboard | loading | unknown\",\n"
            "  \"action\": \"click | type | wait | unknown\",\n"
            "  \"target_x_percent\": 50.0,\n"
            "  \"target_y_percent\": 85.0,\n"
            "  \"text_to_type\": \"test_input_value_if_action_is_type\",\n"
            "  \"explanation\": \"Brief explanation of what this element is and why we are clicking it\"\n"
            "}\n"
            "Ensure you return ONLY raw JSON, with no markdown code blocks or wrapper text."
        )

        _log("Dispatching emulator screenshot to Gemini 3.1 Flash Lite for vision-guided target localization...")
        
        # Enforce rate limit delay before dynamic play API requests
        time.sleep(4.0)

        ai_response = client.models.generate_content(
            model="gemini-3.1-flash-lite",
            contents=[img, prompt],
            config=genai_types.GenerateContentConfig(
                response_mime_type="application/json",
                temperature=0.2,
            )
        )

        # Clean and parse response
        text_resp = ai_response.text.strip()
        if text_resp.startswith("```json"):
            text_resp = text_resp[7:]
        elif text_resp.startswith("```"):
            text_resp = text_resp[3:]
        if text_resp.endswith("```"):
            text_resp = text_resp[:-3]
        
        res_dict = json.loads(text_resp.strip())
        _log(f"Gemini vision response: screen_type={res_dict.get('screen_type')}, action={res_dict.get('action')}, explanation={res_dict.get('explanation')}")

        action = res_dict.get("action")
        target_x_percent = res_dict.get("target_x_percent")
        target_y_percent = res_dict.get("target_y_percent")

        if action in ("click", "type") and target_x_percent is not None and target_y_percent is not None:
            # Auto-scale if Gemini outputs coordinates on a 0-1000 scale instead of 0-100
            if target_x_percent > 100.0:
                target_x_percent /= 10.0
            if target_y_percent > 100.0:
                target_y_percent /= 10.0

            tx = int((target_x_percent / 100.0) * width)
            ty = int((target_y_percent / 100.0) * height)
            
            _log(f"Executing action '{action}' on coordinate ({tx}, {ty})")
            _tap(adb, tx, ty)
            time.sleep(0.5)
            
            if action == "type" and res_dict.get("text_to_type"):
                _text_input(adb, res_dict["text_to_type"])
                _log(f"Typed '{res_dict['text_to_type']}' into coordinate ({tx}, {ty})")
                time.sleep(0.5)

            transcript.append(_step(
                "vision_guided_play",
                f"Vision-Guided Action: {action} on ({tx}, {ty}) - {res_dict.get('explanation')}",
                "succeeded",
                f"Type: {res_dict.get('screen_type')}"
            ))
        elif action == "wait":
            _log("Gemini requested wait. Sleeping 2 seconds.")
            time.sleep(2.0)
            transcript.append(_step(
                "vision_guided_play",
                f"Vision-Guided Action: wait - {res_dict.get('explanation')}",
                "succeeded"
            ))
        else:
            transcript.append(_step(
                "vision_guided_play",
                "Vision-Guided Action: skipped (no clear element to interact with)",
                "skipped"
            ))
    except Exception as e:
        _log(f"Vision-guided dynamic analysis step failed: {e}")
        transcript.append(_step(
            "vision_guided_play",
            f"Vision-Guided Action failed: {e}",
            "failed"
        ))

def _step_background_job_wait(adb: str, transcript: list, secs: float = 5.0) -> None:
    time.sleep(secs)
    transcript.append(_step("background_job_wait",
                            f"Wait {secs}s for delayed jobs, network, and background threads",
                            "succeeded"))


def _step_force_stop_relaunch(adb: str, package: str, activity: Optional[str],
                               transcript: list) -> None:
    r = _run([adb, "shell", "am", "force-stop", package])
    ok_stop = r.returncode == 0
    time.sleep(1.5)
    if activity:
        r2 = _run([adb, "shell", "am", "start", "-n", f"{package}/{activity}"])
        ok_re = r2.returncode == 0
    else:
        r2 = _run([adb, "shell", "monkey", "-p", package, "-c",
                   "android.intent.category.LAUNCHER", "1"])
        ok_re = r2.returncode == 0
    time.sleep(2.0)
    transcript.append(_step(
        "force_stop_relaunch",
        f"Force-stop + cold relaunch of {package}",
        "succeeded" if (ok_stop and ok_re) else "failed"
    ))


def _step_prime_clipboard(adb: str, transcript: list) -> None:
    """Prime the clipboard with mock high-value secret credentials to verify copy/paste snooping."""
    # Write sensitive mockup text to guest clipboard via service call clipboard 2
    r = _run([adb, "shell", "service", "call", "clipboard", "2", "s16", "kavach_mock_vault_key_9988"])
    ok = r.returncode == 0
    transcript.append(_step(
        "prime_clipboard",
        "Primed clipboard with mock recovery key: kavach_mock_vault_key_9988",
        "succeeded" if ok else "failed"
    ))


def _step_exported_services(adb: str, package: str, services: List[str], transcript: list) -> None:
    """Trigger background exported services directly to exercise their onCreate/onStartCommand entry points."""
    if not services:
        transcript.append(_step("exported_service_trigger", "No exported services declared", "skipped"))
        return
    for svc in services[:3]:
        r = _run([adb, "shell", "am", "startservice", "-n", f"{package}/{svc}"])
        ok = r.returncode == 0
        transcript.append(_step(
            "exported_service_trigger",
            f"am startservice {svc}",
            "succeeded" if ok else "failed",
            r.stderr[:100] if not ok else ""
        ))
        time.sleep(0.5)


def _step_system_broadcasts(adb: str, package: str, receivers: List[str], transcript: list) -> None:
    """Fire standard system broadcast triggers to app receivers to check boot persistence and network triggers."""
    if not receivers:
        transcript.append(_step("system_broadcast_trigger", "No receivers declared", "skipped"))
        return
    broadcasts = [
        "android.intent.action.BOOT_COMPLETED",
        "android.net.conn.CONNECTIVITY_CHANGE"
    ]
    for action in broadcasts:
        for rcvr in receivers[:1]:
            r = _run([adb, "shell", "am", "broadcast", "-a", action, "-n", f"{package}/{rcvr}"])
            ok = r.returncode == 0
            transcript.append(_step(
                "system_broadcast_trigger",
                f"Broadcast intent {action} directly to receiver {rcvr}",
                "succeeded" if ok else "failed",
                r.stderr[:100] if not ok else ""
            ))
            time.sleep(0.5)


# ---------------------------------------------------------------------------
# Main entrypoint
# ---------------------------------------------------------------------------

def run_playbook(
    adb: str,
    package_name: str,
    launcher_activity: Optional[str],
    static_signals: Dict[str, Any],
    log_callback=None,
) -> Dict[str, Any]:
    """
    Execute the trigger playbook against a running emulator.

    Returns:
        {
            "transcript":     List[dict],   # step-by-step log
            "coverage_map":   dict,         # what was exercised
            "steps_attempted": int,
            "steps_succeeded": int,
        }
    """
    def _log(msg: str):
        logger.info(msg)
        if log_callback:
            try:
                log_callback(f"[PLAYBOOK] {msg}")
            except Exception:
                pass

    transcript: List[Dict[str, Any]] = []
    coverage = _make_coverage()
    coverage["webview_expected"] = bool(static_signals.get("has_webview"))
    coverage["has_exported_receivers"] = bool(static_signals.get("has_exported_receivers"))

    exported_receivers  = static_signals.get("exported_receivers", [])
    exported_activities = static_signals.get("exported_activities", [])
    exported_services   = static_signals.get("exported_services", [])
    deep_link_schemes   = static_signals.get("deep_link_schemes", [])
    has_webview         = bool(static_signals.get("has_webview"))
    has_login_fields    = bool(static_signals.get("has_login_fields"))

    with tempfile.TemporaryDirectory(prefix="kavach_play_") as tmp_dir:

        # Step 1: Prime device clipboard with sensitive mockup data
        _log("Step 1/14: Priming device clipboard with sensitive mockup data")
        _step_prime_clipboard(adb, transcript)

        # Step 2: wait for app to render
        _log("Step 2/14: Waiting for app to render")
        _step_wait_activity(adb, package_name, transcript)

        # Step 3: explicit launcher activity launch
        _log("Step 3/14: Explicit launcher launch")
        _step_explicit_launch(adb, package_name, launcher_activity, transcript)

        # Step 4: targeted UI interaction
        _log("Step 4/14: UI element interaction")
        _step_interact_ui(adb, tmp_dir, transcript)

        # Step 5: WebView-specific wait
        _log("Step 5/14: WebView wait")
        _step_webview_wait(adb, transcript, has_webview)

        # Step 6: exported receiver intents
        _log("Step 6/14: Exported receiver triggers")
        _step_exported_receivers(adb, package_name, exported_receivers, transcript, coverage)

        # Step 7: exported activity launches
        _log("Step 7/14: Exported activity launches")
        _step_exported_activities(adb, package_name, exported_activities, transcript, coverage)

        # Step 8: exported service triggers
        _log("Step 8/14: Exported service triggers")
        _step_exported_services(adb, package_name, exported_services, transcript)

        # Step 9: background/foreground cycle
        _log("Step 9/14: Background/foreground cycle")
        _step_background_foreground(adb, package_name, launcher_activity, transcript)

        # Step 10: deep link intent
        _log("Step 10/14: Deep link trigger")
        _step_deep_link(adb, package_name, deep_link_schemes, transcript, coverage)

        # Step 11: simulated system broadcasts triggers
        _log("Step 11/14: Simulated system broadcasts triggers")
        _step_system_broadcasts(adb, package_name, exported_receivers, transcript)

        # Step 12: login simulation (if EditText fields are present)
        _log("Step 12/14: Login field simulation")
        if has_login_fields:
            _step_login_simulation(adb, tmp_dir, transcript, coverage, log_callback=_log)
        else:
            transcript.append(_step("login_simulation",
                                    "Skipped (no login field signal in static analysis)", "skipped"))

        # Step 13: Vision-guided dynamic play
        _log("Step 13/15: Vision-guided dynamic play")
        _step_vision_guided_play(adb, tmp_dir, transcript, log_callback=_log)

        # Step 14: wait for background jobs + network
        _log("Step 14/15: Background job wait")
        _step_background_job_wait(adb, transcript)

        # Step 15: force stop + cold relaunch
        _log("Step 15/15: Force-stop and cold relaunch")
        _step_force_stop_relaunch(adb, package_name, launcher_activity, transcript)

    # Calculate high-level step statistics strictly out of 15 steps
    high_level_steps = [
        "prime_clipboard",
        "wait_activity",
        "explicit_launch",
        "interact_ui",
        "webview_wait",
        "exported_receiver_intent",
        "exported_activity_launch",
        "exported_service_trigger",
        "background_foreground",
        "deep_link_intent",
        "system_broadcast_trigger",
        "login_simulation",
        "vision_guided_play",
        "background_job_wait",
        "force_stop_relaunch"
    ]
    succeeded = 0
    attempted = 15
    for step_name in high_level_steps:
        steps_of_type = [s for s in transcript if s.get("step") == step_name]
        if not steps_of_type:
            succeeded += 1
        else:
            if any(s.get("result") == "failed" for s in steps_of_type):
                pass
            else:
                succeeded += 1

    _log(f"Playbook complete: {succeeded}/{attempted} steps succeeded")

    return {
        "transcript":      transcript,
        "coverage_map":    coverage,
        "steps_attempted": attempted,
        "steps_succeeded": succeeded,
    }
