#!/usr/bin/env python3
import json
import time
import os
import logging
import datetime
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import WebDriverException
import random
from selenium_stealth import stealth
from selenium.webdriver.common.keys import Keys
from dotenv import load_dotenv
from selenium.webdriver.support.ui import WebDriverWait

import pyautogui

# from vpn_manager import reconnect_vpn, disconnect_vpn, rotate_server_in_ovpn


pyautogui.FAILSAFE = True  # move mouse to top-left to abort if needed

# get_x_code_from_gmx.py
import os, time, re, imaplib, email, datetime, logging
from email.header import decode_header, make_header
from html import unescape

import undetected_chromedriver as uc

try:
    from bs4 import BeautifulSoup  # pip install beautifulsoup4
    HAVE_BS4 = True
except Exception:
    HAVE_BS4 = False

# ----------- CONFIG -----------
# GMX_USER = os.getenv("GMX_USER") or "cla1cmichl@gmx.com"
# GMX_PASS = os.getenv("GMX_PASS") or "s8Wbz8wu14"
IMAP_HOST = "imap.gmx.com"
IMAP_PORT = 993

R_RAMB_HOST = "imap.rambler.ru"
R_RAMB_PORT = 993

TWITTER_LOGIN_URL = "https://twitter.com/i/flow/login"

# X/Twitter typical senders & subject hints
SENDER_WHITELIST = {"noreply@twitter.com", "security@twitter.com"}
SUBJECT_HINTS = {"verification", "confirm", "login", "code", "twitter", "x"}

# Timeout/polling
TOTAL_TIMEOUT_SEC = 120
POLL_INTERVAL_SEC = 5
MAX_FETCH = 60  # check only latest N messages for speed

# Logging
logging.basicConfig(level=logging.INFO, format="%(message)s")

# ----------- CODE EXTRACTION LOGIC -----------

# Allow 6–12 alphanumeric; X often uses 8-char tokens. Adjust if needed.
ALNUM_CODE = re.compile(r"^[A-Za-z0-9]{6,12}$")

# Avoid words that commonly appear around the code
STOPWORDS = {
    "account","twitter","support","security","verification","confirm","code",
    "thanks","team","hello","login","attempt","protect","change","password",
    "review","apps","learn","more","now","this","was","you","your","singleuse",
    "enter","following"
}

TRIGGER_PAT = re.compile(r"(single[-\s]?use\s+code|enter.*code|verification\s+code)", re.I)

def rand_sleep(a=0.05, b=0.18):
    time.sleep(random.uniform(a, b))

def is_anti_bot_triggered(driver):
    """Detects Cloudflare, CAPTCHA, or login-verification blocks."""
    try:
        title = driver.title.lower()
        url = driver.current_url.lower()
        page_source = driver.page_source.lower()

        # Common Cloudflare / CAPTCHA patterns
        if "just a moment" in title or "checking your browser" in page_source:
            return True
        if "captcha" in title or "captcha" in url or "captcha" in page_source:
            return True
        if "verify your identity" in page_source or "unusual login" in page_source:
            return True
        if "challenge" in url or "suspended" in url:
            return True

        return False
    except Exception:
        return False

def start_driver_with_proxy(proxy=None, use_uc=True):
    """
    Start a new undetected-chrome driver with a fresh profile and optional proxy.
    Returns driver.
    """
    import tempfile, os, time
    profile = os.path.join(tempfile.gettempdir(), f"uc_profile_{int(time.time()*1000)}")
    os.makedirs(profile, exist_ok=True)

    if use_uc:
        # import undetected_chromedriver as uc
        options = uc.ChromeOptions()
        options.add_argument(f"--user-data-dir={profile}")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_argument("--accept-lang=en-US,en;q=0.9")
        # random window size / UA as in file
        w = random.randint(1050, 1300); h = random.randint(800, 950)
        options.add_argument(f"--window-size={w},{h}")
        if proxy:
            options.add_argument(f"--proxy-server={proxy}")
        driver = uc.Chrome(options=options)
        # lightweight stealth patches (uc already helps)
        try:
            driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {
                "source": "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"
            })
        except Exception:
            pass
        return driver
    else:
        # fallback to selenium.webdriver.Chrome if needed (less stealthy)
        # from selenium import webdriver
        opts = webdriver.ChromeOptions()
        opts.add_argument(f"--user-data-dir={profile}")
        if proxy:
            opts.add_argument(f"--proxy-server={proxy}")
        return webdriver.Chrome(options=opts)

def launch_uc_driver():

    options = uc.ChromeOptions()
    # keep your own arguments (window size, user-agent, proxy, etc.)
    options.add_argument("--window-size=1200,900")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")

    driver = uc.Chrome(options=options)
    # extra stealth script (uc already does a lot)
    try:
        driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {
            "source": """
            Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
            if (!window.chrome) { window.chrome = { runtime: {} }; }
            try { Object.defineProperty(navigator, 'plugins', {get: () => [1,2,3]}); } catch(e) {}
            """
        })
    except Exception:
        pass

    return driver
    
def wait_for_cloudflare_manual_solve(driver, timeout=300, poll=1):
    """
    Wait for Cloudflare / 'Just a moment...' / checkbox verification to disappear.
    Prompts operator to solve it manually in the visible browser.
    Returns True if verification cleared, False on timeout.
    """
    start = time.time()
    print("\n--- Cloudflare check detected — please solve it manually in the browser. ---")
    print("When complete press ENTER here, or wait until page transitions automatically.\n")

    while time.time() - start < timeout:
        try:
            url = driver.current_url.lower()
            # Common texts that indicate Cloudflare/verification page
            body_text = driver.execute_script("return document.body ? document.body.innerText : ''") or ""

            # Detect Cloudflare challenge elements / texts
            cf_indicators = [
                "just a moment", "verify you are human", "checking your browser", "please enable javascript",
                "cloudflare", "verify you're human"
            ]
            showing_cf = any(s in body_text.lower() for s in cf_indicators)

            # Also check for known iframe checks (many sites embed cloudflare widget in an iframe)
            iframes = driver.find_elements(By.TAG_NAME, "iframe")
            iframe_cf = any("cloudflare" in (ifr.get_attribute("src") or "").lower() or "captcha" in (ifr.get_attribute("src") or "").lower() for ifr in iframes)

            if not showing_cf and not iframe_cf:
                # Looks cleared
                print("No Cloudflare challenge detected on page (or it cleared). Continuing.")
                return True

            # If we reach here there is still a challenge
            # Non-blocking: check if operator pressed ENTER (stdin)
            # Note: in many environments stdin is not available; user can also just solve and wait for auto transition.
            import select
            if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                _ = sys.stdin.readline()
                # operator pressed enter -> re-check immediately
                time.sleep(0.5)
                continue

            time.sleep(poll)
        except Exception:
            time.sleep(poll)

    print("Timeout waiting for Cloudflare verification to be solved.")
    return False


def _decode_subject(msg):
    raw = msg.get("Subject", "")
    try:
        return str(make_header(decode_header(raw)))
    except Exception:
        return raw

def _from_addr(msg):
    return email.utils.parseaddr(msg.get("From", ""))[1].lower()

def _looks_like_x(msg):
    frm = _from_addr(msg)
    if frm in SENDER_WHITELIST:
        return True
    subj = _decode_subject(msg).lower()
    return any(k in subj for k in SUBJECT_HINTS)

def _get_parts_text(msg):
    """Return (html_text, plain_text) from email message."""
    htmls, plains = [], []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = (part.get_content_type() or "").lower()
            dispo = (part.get("Content-Disposition") or "").lower()
            if "attachment" in dispo:
                continue
            payload = part.get_payload(decode=True) or b""
            charset = part.get_content_charset() or "utf-8"
            try:
                text = payload.decode(charset, errors="replace")
            except Exception:
                text = payload.decode("utf-8", errors="replace")
            if ctype == "text/html":
                htmls.append(text)
            elif ctype == "text/plain":
                plains.append(text)
    else:
        payload = msg.get_payload(decode=True) or b""
        charset = msg.get_content_charset() or "utf-8"
        text = payload.decode(charset, errors="replace")
        if (msg.get_content_type() or "").lower() == "text/html":
            htmls.append(text)
        else:
            plains.append(text)
    return ("\n".join(htmls), "\n".join(plains))

def _extract_code_from_text(full_text: str) -> str | None:
    # Normalize lines
    lines = [ln.strip() for ln in full_text.replace("\r", "").split("\n")]

    # 1) Take the line after the trigger sentence
    for i, ln in enumerate(lines):
        if TRIGGER_PAT.search(ln):
            for j in range(i + 1, min(i + 6, len(lines))):
                cand = lines[j].strip()
                if not cand:
                    continue
                cand = cand.strip("“”\"'<>[](){}:;,.")
                if ALNUM_CODE.match(cand) and cand.lower() not in STOPWORDS:
                    return cand

    # 2) Standalone candidates (no spaces/punct), avoid common words
    candidates = []
    for ln in lines:
        cand = ln.strip("“”\"'<>[](){}:;,.")
        if ALNUM_CODE.match(cand) and cand.lower() not in STOPWORDS and " " not in ln:
            candidates.append(cand)

    # Prefer 8–10 chars (often correct), then shorter/longer in range
    candidates.sort(key=lambda x: (not (8 <= len(x) <= 10), len(x)))
    return candidates[0] if candidates else None

def extract_code(html_text: str, plain_text: str, subject_text: str) -> str | None:
    # Prefer HTML text (often contains the code on its own line or inside <strong>/<code>)
    if html_text:
        if HAVE_BS4:
            soup = BeautifulSoup(html_text, "html.parser")
            # Build a readable, line-based text
            # First use visible strong/b/code blocks (common for codes)
            emphasis = [el.get_text("\n", strip=True) for el in soup.find_all(["code","strong","b"])]
            for chunk in emphasis:
                code = _extract_code_from_text(unescape(chunk))
                if code:
                    return code
            # Then full message text
            text = soup.get_text("\n", strip=True)
            code = _extract_code_from_text(unescape(text))
            if code:
                return code
        else:
            # No bs4: fallback to stripping tags crudely
            text = re.sub(r"<[^>]+>", "\n", html_text)
            text = unescape(text)
            code = _extract_code_from_text(text)
            if code:
                return code

    # Plain text fallback
    code = _extract_code_from_text(plain_text or "")
    if code:
        return code

    # As a last resort, check subject
    return _extract_code_from_text(subject_text or "")


# ----------- IMAP FETCH -----------

# ----------- IMAP FETCH (Rambler) -----------

def fetch_latest_x_code_rambler(rambler_user: str, rambler_pass: str,
                                timeout_sec=TOTAL_TIMEOUT_SEC,
                                poll_interval=POLL_INTERVAL_SEC):
    """
    Fetch latest X/Twitter confirmation code from a Rambler IMAP account.
    Implementation parallels fetch_latest_x_code(...) for GMX.
    """
    end = time.time() + timeout_sec
    try:
        with imaplib.IMAP4_SSL(R_RAMB_HOST, R_RAMB_PORT) as M:
            logging.info("Connecting to Rambler IMAP…")
            M.login(rambler_user, rambler_pass)
            logging.info("Rambler IMAP login OK.")
            while time.time() < end:
                for mailbox in ("INBOX", "Spam", "Junk"):
                    try:
                        typ, _ = M.select(mailbox)
                        if typ != "OK":
                            continue
                    except imaplib.IMAP4.error:
                        continue

                    ids = _search_ids(M, "UNSEEN")
                    if not ids:
                        ids = _search_ids(M, "ALL")

                    ids_sorted = _sorted_recent_ids(M, ids)

                    for msg_id in ids_sorted:
                        typ, msg_data = M.fetch(msg_id, "(RFC822)")
                        if typ != "OK" or not msg_data or not msg_data[0]:
                            continue
                        msg = email.message_from_bytes(msg_data[0][1])

                        if not _looks_like_x(msg):
                            continue

                        subject = _decode_subject(msg)
                        frm = _from_addr(msg)
                        html_text, plain_text = _get_parts_text(msg)

                        code = extract_code(html_text, plain_text, subject)
                        if code:
                            logging.info(f"Matched Rambler message: From={frm} | Subject={subject}")
                            return code

                time.sleep(poll_interval)
    except Exception as e:
        logging.warning(f"Rambler IMAP fetch error: {e}")
    return None


def _search_ids(M, query):
    typ, data = M.search(None, query)
    if typ != "OK":
        return []
    return data[0].split()

def _sorted_recent_ids(M, ids):
    """Sort by INTERNALDATE newest->oldest and cap to MAX_FETCH."""
    dated = []
    for msg_id in ids[-MAX_FETCH:]:
        typ, meta = M.fetch(msg_id, "(INTERNALDATE)")
        if typ != "OK" or not meta or not meta[0]:
            continue
        meta_str = meta[0].decode(errors="ignore")
        try:
            dts = meta_str.split('"')[1]
            dt = datetime.datetime.strptime(dts, "%d-%b-%Y %H:%M:%S %z")
        except Exception:
            dt = datetime.datetime.min.replace(tzinfo=datetime.timezone.utc)
        dated.append((dt, msg_id))
    dated.sort(key=lambda x: x[0], reverse=True)
    return [mid for _, mid in dated]

def fetch_latest_x_code(gmx_user:str, gmx_pass:str, timeout_sec=TOTAL_TIMEOUT_SEC, poll_interval=POLL_INTERVAL_SEC):
    end = time.time() + timeout_sec
    with imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT) as M:
        logging.info("Connecting to GMX IMAP…")

        M.login(gmx_user, gmx_pass)
        logging.info("Login OK.")

        while time.time() < end:
            for mailbox in ("INBOX", "Spam"):
                try:
                    typ, _ = M.select(mailbox)
                    if typ != "OK":
                        continue
                except imaplib.IMAP4.error:
                    continue

                # Prefer unseen; if none, check all (recent)
                ids = _search_ids(M, "UNSEEN")
                if not ids:
                    ids = _search_ids(M, "ALL")

                ids_sorted = _sorted_recent_ids(M, ids)

                for msg_id in ids_sorted:
                    typ, msg_data = M.fetch(msg_id, "(RFC822)")
                    if typ != "OK" or not msg_data or not msg_data[0]:
                        continue
                    msg = email.message_from_bytes(msg_data[0][1])

                    if not _looks_like_x(msg):
                        continue

                    subject = _decode_subject(msg)
                    frm = _from_addr(msg)
                    html_text, plain_text = _get_parts_text(msg)

                    code = extract_code(html_text, plain_text, subject)
                    if code:
                        logging.info(f"Matched message: From={frm} | Subject={subject}")
                        return code

            time.sleep(poll_interval)
    return None

# Setup logging first
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

# Set output directory based on environment
running_in_docker = os.environ.get("RUNNING_IN_DOCKER", "false").lower() == "true"
if running_in_docker:
    OUTPUT_DIR = "/app/cookies"
    logger.info("Docker environment detected, saving cookies to /app/cookies")
else:
    OUTPUT_DIR = "../cookies"
    logger.info("Local environment detected, saving cookies to ../cookies")

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Twitter cookie names to extract
COOKIE_NAMES = ["personalization_id", "kdt", "twid", "ct0", "auth_token", "att"]

# Twitter domains to handle - We will only use twitter.com
TWITTER_DOMAINS = ["twitter.com"]

# Twitter login URL
TWITTER_LOGIN_URL = "https://twitter.com/i/flow/login"

# Constants
POLLING_INTERVAL = 1  # Check every 1 second
WAITING_TIME = 300  # Wait up to 5 minutes for manual verification
CLICK_WAIT = 5  # Wait 5 seconds after clicking buttons


def get_future_date(days=7, hours=0, minutes=0, seconds=0):
    """
    Generate a slightly randomized ISO 8601 date string for a specified time in the future.

    Args:
        days: Number of days in the future
        hours: Number of hours to add
        minutes: Number of minutes to add
        seconds: Number of seconds to add

    Returns:
        ISO 8601 formatted date string with slight randomization
    """
    # Add slight randomization to make cookies appear more natural
    random_seconds = random.uniform(0, 3600)  # Random seconds (up to 1 hour)
    random_minutes = random.uniform(0, 60)  # Random minutes (up to 1 hour)

    future_date = datetime.datetime.now() + datetime.timedelta(
        days=days,
        hours=hours,
        minutes=minutes + random_minutes,
        seconds=seconds + random_seconds,
    )

    # Format in ISO 8601 format with timezone information
    return future_date.strftime("%Y-%m-%dT%H:%M:%SZ")


def create_cookie_template(name, value, domain="twitter.com", expires=None):
    """
    Create a standard cookie template with the given name and value.
    Note: Cookie values should not contain double quotes as they cause errors in Go's HTTP client.

    Args:
        name: Name of the cookie
        value: Value of the cookie
        domain: Domain for the cookie
        expires: Optional expiration date string in ISO 8601 format
    """
    # Ensure no quotes in cookie value to prevent HTTP header issues
    if value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    value = value.replace('"', "")

    # If no expiration date is provided, use the default "0001-01-01T00:00:00Z"
    if expires is None:
        expires = "0001-01-01T00:00:00Z"

    return {
        "Name": name,
        "Value": value,
        "Path": "",
        "Domain": domain,
        "Expires": expires,
        "RawExpires": "",
        "MaxAge": 0,
        "Secure": False,
        "HttpOnly": False,
        "SameSite": 0,
        "Raw": "",
        "Unparsed": None,
    }


def setup_realistic_profile(temp_profile):
    """Set up a more realistic browser profile with history and common extensions."""

    # Create history file structure
    history_dir = os.path.join(temp_profile, "Default")
    os.makedirs(history_dir, exist_ok=True)

    # Sample visited sites for history (just structure, not actual data)
    common_sites = [
        "google.com",
        "youtube.com",
        "facebook.com",
        "amazon.com",
        "wikipedia.org",
    ]

    # Create a dummy history file
    history_file = os.path.join(history_dir, "History")
    try:
        with open(history_file, "w") as f:
            # Just create an empty file to simulate history presence
            f.write("")

        # Create bookmark file with common sites
        bookmarks_file = os.path.join(history_dir, "Bookmarks")
        bookmarks_data = {
            "roots": {
                "bookmark_bar": {
                    "children": [
                        {"name": site, "url": f"https://{site}"}
                        for site in common_sites
                    ],
                    "date_added": str(int(time.time())),
                    "date_modified": str(int(time.time())),
                    "name": "Bookmarks Bar",
                    "type": "folder",
                }
            },
            "version": 1,
        }
        with open(bookmarks_file, "w") as f:
            json.dump(bookmarks_data, f)

        # Create preferences file with some realistic settings
        preferences_file = os.path.join(history_dir, "Preferences")
        preferences_data = {
            "browser": {
                "last_known_google_url": "https://www.google.com/",
                "last_prompted_google_url": "https://www.google.com/",
                "show_home_button": True,
                "custom_chrome_frame": False,
            },
            "homepage": "https://www.google.com",
            "session": {
                "restore_on_startup": 1,
                "startup_urls": [f"https://{random.choice(common_sites)}"],
            },
            "search": {"suggest_enabled": True},
            "translate": {"enabled": True},
        }
        with open(preferences_file, "w") as f:
            json.dump(preferences_data, f)

        logger.info("Created realistic browser profile with history and preferences")
    except Exception as e:
        logger.warning(f"Failed to create history files: {str(e)}")

    # Add a dummy extension folder to simulate common extensions
    ext_dir = os.path.join(temp_profile, "Default", "Extensions")
    os.makedirs(ext_dir, exist_ok=True)

    # Create dummy extension folders for common extensions
    common_extensions = [
        "aapbdbdomjkkjkaonfhkkikfgjllcleb",  # Google Translate
        "ghbmnnjooekpmoecnnnilnnbdlolhkhi",  # Google Docs
        "cjpalhdlnbpafiamejdnhcphjbkeiagm",  # uBlock Origin
    ]

    for ext_id in common_extensions:
        ext_path = os.path.join(ext_dir, ext_id)
        os.makedirs(ext_path, exist_ok=True)
        # Create a minimal manifest file
        manifest_path = os.path.join(ext_path, "manifest.json")
        try:
            with open(manifest_path, "w") as f:
                f.write("{}")
        except Exception as e:
            logger.warning(f"Failed to create extension manifest: {str(e)}")

    return temp_profile

def element_center_on_screen(driver, element):
    """
    Return (screen_x, screen_y) center coordinates for the element using JS.
    This accounts for window.screenX/Y and browser chrome by using outer/inner heights.
    """
    loc = element.location_once_scrolled_into_view
    size = element.size
    x = loc['x'] + size['width']//2
    y = loc['y'] + size['height']//2 + 100
    return x, y
def click_element_via_pyautogui_btn(driver, element, before_sleep=(0.1,0.3), after_sleep=(0.2,0.5)):
    driver.execute_script("arguments[0].scrollIntoView({block:'center', inline:'center'});", element)
    rand_sleep(*before_sleep)
    x, y = element_center_on_screen(driver, element)
    print(f"[INFO] Moving to ({x},{y}) and clicking (pyautogui)")
    pyautogui.moveTo(x, y , duration=random.uniform(0.2, 0.5))
    pyautogui.click()
    rand_sleep(*after_sleep)

def click_element_via_pyautogui(driver, element, before_sleep=(0.1,0.3), after_sleep=(0.2,0.5)):
    driver.execute_script("arguments[0].scrollIntoView({block:'center', inline:'center'});", element)
    rand_sleep(*before_sleep)
    x, y = element_center_on_screen(driver, element)
    print(f"[INFO] Moving to ({x},{y}) and clicking (pyautogui)")
    pyautogui.moveTo(x, y, duration=random.uniform(0.2, 0.5))
    pyautogui.click()
    rand_sleep(*after_sleep)

def type_via_pyautogui(text, interval=(0.06, 0.18)):
    for ch in text:
        pyautogui.typewrite(ch)
        time.sleep(random.uniform(interval[0], interval[1]))
    rand_sleep(0.12, 0.4)

def setup_driver():
    """Set up and return a Chrome driver using a dedicated profile."""
    logger.info("Setting up Chrome driver...")

    options = webdriver.ChromeOptions()

    # Create a temporary profile directory to avoid conflicts with existing Chrome
    import tempfile

    temp_profile = os.path.join(
        tempfile.gettempdir(), f"chrome_profile_{int(time.time())}"
    )
    os.makedirs(temp_profile, exist_ok=True)
    logger.info(f"Using dedicated Chrome profile at: {temp_profile}")
    options.add_argument(f"--user-data-dir={temp_profile}")

    # Common options
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-blink-features=AutomationControlled")

    # Add anti-cloudflare options
    options.add_argument("--disable-features=IsolateOrigins,site-per-process")
    options.add_argument("--disable-web-security")
    options.add_argument("--allow-running-insecure-content")

    # Add a random viewport size
    width = random.randint(1050, 1200)
    height = random.randint(800, 950)
    options.add_argument(f"--window-size={width},{height}")

    # Add more randomized user agents
    user_agents = [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.2 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    ]
    user_agent = random.choice(user_agents)
    options.add_argument(f"--user-agent={user_agent}")

    # CDP detection evasion
    options.add_argument("--remote-debugging-port=0")
    options.add_argument("--remote-allow-origins=*")

    # Set up more realistic browser profile
    temp_profile = setup_realistic_profile(temp_profile)

    # Add headers to appear more like a genuine browser
    options.add_argument("--accept-lang=en-US,en;q=0.9")
    options.add_argument("--disable-features=IsolateOrigins,site-per-process")

    # Check for proxy environment variables and configure proxy if available
    # This is especially important when running behind a VPN
    proxy_http = os.environ.get("http_proxy")
    proxy_https = os.environ.get("https_proxy")

    if proxy_http or proxy_https:
        proxy_to_use = proxy_http or proxy_https
        logger.info(f"Detected proxy settings: {proxy_to_use}")

        # Format the proxy properly for Chrome
        if proxy_to_use.startswith("http://"):
            proxy_to_use = proxy_to_use[7:]  # Remove http:// prefix

        options.add_argument(f"--proxy-server={proxy_to_use}")
        logger.info(f"Configured Chrome to use proxy: {proxy_to_use}")

        # Add additional settings to help with proxy connectivity
        options.add_argument("--ignore-certificate-errors")
        options.add_argument("--disable-extensions")

    try:
        logger.info("Initializing Chrome driver...")
        driver = webdriver.Chrome(options=options)
        logger.info("Successfully initialized Chrome driver")

        # Additional anti-detection measures
        driver.execute_script(
            "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
        )

        # Apply more comprehensive stealth settings
        stealth(
            driver,
            languages=["en-US", "en"],
            vendor="Google Inc.",
            platform="Win32",
            webgl_vendor="Intel Inc.",
            renderer="Intel Iris OpenGL Engine",
            fix_hairline=True,
            # New parameters
            hardware_concurrency=4,  # Spoof CPU core count
            media_codecs=True,  # Mask media codec capabilities
            audio_context=True,  # Prevent audio fingerprinting
            fonts_languages=["en-US"],  # Standardize font rendering
        )

        # Timezone and geolocation spoofing
        driver.execute_script(
            """
          const fakeTime = new Date('2023-01-01T12:00:00');
          const dateNowStub = () => fakeTime.getTime();
          const realDateNow = Date.now;
          Date.now = dateNowStub;
          const timeStub = () => 12 * 60 * 60 * 1000;
          const realPerformanceNow = performance.now;
          performance.now = timeStub;
        """
        )

        # Spoof geolocation API
        driver.execute_script(
            """
          navigator.geolocation.getCurrentPosition = function(success) {
            success({
              coords: {
                latitude: 37.7749,
                longitude: -122.4194,
                accuracy: 100,
                altitude: null,
                altitudeAccuracy: null,
                heading: null,
                speed: null
              },
              timestamp: Date.now()
            });
          };
        """
        )

        # More comprehensive anti-detection script
        driver.execute_script(
            """
        // Overwrite navigator properties that reveal automation
        const overrideNavigator = () => {
          Object.defineProperty(navigator, 'maxTouchPoints', {
            get: () => 5
          });
          
          Object.defineProperty(navigator, 'hardwareConcurrency', {
            get: () => 8
          });
          
          Object.defineProperty(navigator, 'deviceMemory', {
            get: () => 8
          });
          
          // Override connection type
          if (navigator.connection) {
            Object.defineProperty(navigator.connection, 'type', {
              get: () => 'wifi'
            });
          }
          
          // Override webRTC
          if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
            navigator.mediaDevices.enumerateDevices = () => Promise.resolve([
              {deviceId: 'default', kind: 'audioinput', label: '', groupId: 'default'},
              {deviceId: 'default', kind: 'audiooutput', label: '', groupId: 'default'},
              {deviceId: 'default', kind: 'videoinput', label: '', groupId: 'default'}
            ]);
          }
        };

        // Canvas fingerprint protection
        const overrideCanvas = () => {
          const oldGetContext = HTMLCanvasElement.prototype.getContext;
          HTMLCanvasElement.prototype.getContext = function(type, attributes) {
            const context = oldGetContext.apply(this, arguments);
            if (type === '2d') {
              const oldFillText = context.fillText;
              context.fillText = function() {
                arguments[0] = arguments[0].toString();
                return oldFillText.apply(this, arguments);
              };
              const oldMeasureText = context.measureText;
              context.measureText = function() {
                arguments[0] = arguments[0].toString();
                const result = oldMeasureText.apply(this, arguments);
                result.width += Math.random() * 0.0001;
                return result;
              };
            }
            return context;
          };
        };

        overrideNavigator();
        overrideCanvas();
        """
        )

        return driver
    except Exception as e:
        logger.error(f"Error creating Chrome driver: {str(e)}")
        # Ultimate fallback with minimal options
        try:
            logger.info("Trying with minimal Chrome options...")
            minimal_options = webdriver.ChromeOptions()
            minimal_options.add_argument("--no-sandbox")

            # Add proxy settings to minimal options if available
            if proxy_http or proxy_https:
                proxy_to_use = proxy_http or proxy_https
                if proxy_to_use.startswith("http://"):
                    proxy_to_use = proxy_to_use[7:]  # Remove http:// prefix
                minimal_options.add_argument(f"--proxy-server={proxy_to_use}")
                minimal_options.add_argument("--ignore-certificate-errors")

            driver = webdriver.Chrome(options=minimal_options)
            return driver
        except Exception as e2:
            logger.error(f"Final driver creation attempt failed: {str(e2)}")
            raise


def human_like_typing(element, text):
    """Simulate human-like typing with random delays between keypresses."""
    for char in text:
        element.send_keys(char)
        time.sleep(random.uniform(0.05, 0.25))  # Random delay between keypresses


def find_and_fill_input(driver, input_type, value):
    """Find and fill an input field of a specific type."""
    selectors = {
        "username": [
            'input[autocomplete="username"]',
            'input[name="text"]',
            'input[name="username"]',
            'input[placeholder*="username" i]',
            'input[placeholder*="phone" i]',
            'input[placeholder*="email" i]',
        ],
        "password": [
            'input[type="password"]',
            'input[name="password"]',
            'input[placeholder*="password" i]',
        ],
        "email": [
            'input[type="email"]',
            'input[name="email"]',
            'input[placeholder*="email" i]',
            'input[autocomplete="email"]',
        ],
        "phone": [
            'input[type="tel"]',
            'input[name="phone"]',
            'input[placeholder*="phone" i]',
            'input[autocomplete="tel"]',
        ],
        "code": [
            'input[autocomplete="one-time-code"]',
            'input[name="code"]',
            'input[placeholder*="code" i]',
            'input[placeholder*="verification" i]',
        ],
    }

    if input_type not in selectors:
        logger.warning(f"Unknown input type: {input_type}")
        return False

    input_found = False

    for selector in selectors[input_type]:
        try:
            inputs = driver.find_elements(By.CSS_SELECTOR, selector)
            for input_field in inputs:
                if input_field.is_displayed():
                    # Clear the field first (sometimes needed)
                    # try:
                    #     input_field.clear()
                    # except:
                    #     pass

                    driver.execute_script("arguments[0].scrollIntoView({block:'center'});", input_field)
                    rand_sleep(0.5, 0.8)

                    # bring window to front (best-effort). This may not work in all OSes.
                    try:
                        driver.maximize_window()
                        rand_sleep(1, 2)
                    except Exception:
                        pass
                    
                    # Click username field via OS and type username
                    print("[INFO] Clicking username field and typing via pyautogui (do NOT move mouse/keyboard)...")
                    click_element_via_pyautogui(driver, input_field)
                    rand_sleep(0.22, 0.4)
                    type_via_pyautogui(value)


                    # Type the value
                    # human_like_typing(input_field, value)
                    logger.info(f"Filled {input_type} field with value: {value}")

                    # Add a small delay after typing
                    time.sleep(random.uniform(0.5, 1.5))
                    input_found = True
                    return True
        except Exception as e:
            logger.debug(
                f"Couldn't find or fill {input_type} field with selector {selector}: {str(e)}"
            )

    if not input_found:
        logger.info(f"No {input_type} input field found")

    return False

# def check_banner_errors(driver):
#     # Check for error banner
#     try:
#         err = driver.find_elements(By.XPATH, "//*[contains(text(), 'Could not log you in') or contains(text(), 'try again later') or contains(text(), 'Something went wrong')]")
#         if any(e.is_displayed() for e in err):
#             print("[ERROR] Site returned 'Could not log you in' — likely rate-limited or blocked.")
#             return False, []
#     except Exception:
#         pass

# def wait_for_password_field(driver, timeout=10):
# # Wait for either password input or error banner
#     try:
#         WebDriverWait(driver, timeout).until(
#             EC.any_of(
#                 EC.presence_of_element_located((By.CSS_SELECTOR, 'input[name="password"]')),
#                 EC.presence_of_element_located((By.XPATH, "//*[contains(text(), 'Could not log you in') or contains(text(), 'try again later') or contains(text(), 'Something went wrong')]"))
#             )
#         )
#     except Exception:
#         # fallback small sleep
#         time.sleep(1.0)

    
def click_next_button(driver):
    """Try to click a 'Next' or submit button."""
    button_clicked = False
    next_el = None
    # Try buttons with "Next" text
    try:
        next_buttons = driver.find_elements(
            By.XPATH, '//*[contains(text(), "Next") or contains(text(), "next")]'
        )
        for button in next_buttons:
            if button.is_displayed():
                next_el = button
                # button.click()
                # logger.info("Clicked Next button by text")
                button_clicked = True
                break
    except Exception as e:
        logger.debug(f"Couldn't click Next button by text: {str(e)}")

    # Try buttons with "Continue" text
    if not button_clicked:
        try:
            continue_buttons = driver.find_elements(
                By.XPATH,
                '//*[contains(text(), "Continue") or contains(text(), "continue")]',
            )
            for button in continue_buttons:
                if button.is_displayed():
                    # button.click()
                    next_el = button
                    logger.info("Clicked Continue button by text")
                    button_clicked = True
                    break
        except Exception as e:
            logger.debug(f"Couldn't click Continue button by text: {str(e)}")

    # Try buttons with "Log in" or "Sign in" text
    if not button_clicked:
        try:
            login_buttons = driver.find_elements(
                By.XPATH,
                '//*[contains(text(), "Log in") or contains(text(), "Login") or contains(text(), "Sign in")]',
            )
            for button in login_buttons:
                if button.is_displayed():
                    #button.click()
                    next_el = button
                    logger.info("Clicked Login button by text")
                    button_clicked = True
                    break
        except Exception as e:
            logger.debug(f"Couldn't click Login button by text: {str(e)}")

    # Try generic button elements by role
    if not button_clicked:
        try:
            buttons = driver.find_elements(By.CSS_SELECTOR, 'div[role="button"]')
            for button in buttons:
                if button.is_displayed():
                    # button.click()
                    next_el = button
                    logger.info("Clicked button by role")
                    button_clicked = True
                    break
        except Exception as e:
            logger.debug(f"Couldn't click button by role: {str(e)}")

    # Try submitting the form with Enter key (last resort)
    if not button_clicked:
        try:
            active_element = driver.switch_to.active_element
            active_element.send_keys(Keys.ENTER)
            logger.info("Pressed Enter key on active element")
            button_clicked = True
        except Exception as e:
            logger.debug(f"Couldn't press Enter key: {str(e)}")


    # Click Next via pyautogui
    click_element_via_pyautogui_btn(driver, next_el)

   
    return button_clicked


def is_logged_in(driver):
    """Check if user is logged in to Twitter."""
    try:
        current_url = driver.current_url.lower()

        # URL check (most reliable)
        if "twitter.com/home" in current_url or "x.com/home" in current_url:
            return True

        # Home timeline check
        home_timeline = driver.find_elements(
            By.CSS_SELECTOR, 'div[aria-label="Timeline: Your Home Timeline"]'
        )
        if home_timeline and any(elem.is_displayed() for elem in home_timeline):
            return True

        # Tweet/Post button check
        tweet_buttons = driver.find_elements(
            By.CSS_SELECTOR,
            'a[data-testid="SideNav_NewTweet_Button"], [data-testid="tweetButtonInline"]',
        )
        if tweet_buttons and any(btn.is_displayed() for btn in tweet_buttons):
            return True

        # Navigation elements check
        nav_elements = driver.find_elements(
            By.CSS_SELECTOR,
            'nav[role="navigation"], a[data-testid="AppTabBar_Home_Link"]',
        )
        if nav_elements and any(elem.is_displayed() for elem in nav_elements):
            return True

        return False
    except Exception as e:
        logger.error(f"Error checking login status: {str(e)}")
        return False


def needs_verification(driver):
    """Check if the page is showing a verification or authentication screen."""
    try:
        # Check for verification text
        verification_texts = [
            "Authenticate your account",
            "Enter your phone number",
            "Enter your email",
            "Check your phone",
            "Check your email",
            "Verification code",
            "verify your identity",
            "unusual login activity",
            "suspicious activity",
            "Help us keep your account safe",
            "Verify your identity",
            "keep your account safe",
            "Confirmation code"
        ]

        for text in verification_texts:
            try:
                elements = driver.find_elements(
                    By.XPATH, f"//*[contains(text(), '{text}')]"
                )
                if elements and any(elem.is_displayed() for elem in elements):
                    logger.info(f"Verification needed: Found text '{text}'")
                    return True
            except:
                pass

        # Check for verification URLs
        current_url = driver.current_url.lower()
        verification_url_patterns = [
            "verify",
            "challenge",
            "confirm",
            "auth",
            "login_challenge",
        ]

        for pattern in verification_url_patterns:
            if pattern in current_url:
                logger.info(f"Verification needed: URL contains '{pattern}'")
                return True

        return False
    except Exception as e:
        logger.error(f"Error checking for verification: {str(e)}")
        return False


def extract_email_from_password(password, accindex):
    """Extract email from password assuming format 'himynameis<name>'."""
    # Get base email from environment variable - required
    email_list = os.environ.get("TWITTER_EMAIL").split("+")
    base_email = email_list[accindex]
    if not base_email:
        logger.error("TWITTER_EMAIL environment variable not set. This is required.")
        # Return a placeholder that will likely fail but doesn't expose personal info
        return "email_not_configured@example.com"

    # Extract the username part from base email for plus addressing
    base_username = base_email.split("@")[0]
    domain = base_email.split("@")[1]

    try:
        # Check if password starts with 'himynameis'
        if password.startswith("himynameis"):
            name = password[10:]  # Extract everything after 'himynameis'
            return f"{base_username}+{name}@{domain}"
    except:
        pass

    # Fall back to the base email
    return base_email

def extract_gmx_password(accindex):
    
    password_list = os.environ.get("TWITTER_EMAIL_PASSWORD").split("+")
    password = password_list[accindex]
    if not password:
        logger.error("TWITTER_EMAIL_PASSWORD environment variable not set. This is required.")
        return "notconfigured"

    return password


def extract_cookies(driver):
    """Extract cookies from the browser."""
    logger.info("Extracting cookies")
    browser_cookies = driver.get_cookies()
    logger.info(f"Found {len(browser_cookies)} cookies total")

    cookie_values = {}
    used_domain = "twitter.com"  # Always use twitter.com domain, no conditional check

    for cookie in browser_cookies:
        if cookie["name"] in COOKIE_NAMES:
            value = cookie["value"]
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]  # Remove surrounding quotes
            value = value.replace('"', "")  # Replace any remaining quotes

            cookie_values[cookie["name"]] = value
            logger.info(f"Found cookie: {cookie['name']}")

    # Log missing cookies
    missing_cookies = [name for name in COOKIE_NAMES if name not in cookie_values]
    if missing_cookies:
        logger.warning(f"Missing cookies: {', '.join(missing_cookies)}")
    else:
        logger.info("All required cookies found")

    return cookie_values, used_domain


def generate_cookies_json(cookie_values, domain="twitter.com"):
    """Generate the cookies JSON from the provided cookie values."""
    # Always use twitter.com domain regardless of what's passed in
    domain = "twitter.com"
    logger.info(f"Generating cookies JSON for domain: {domain}")

    # Determine expiration dates for different cookie types
    one_week_future = get_future_date(days=7)
    one_month_future = get_future_date(days=30)

    cookies = []
    for name in COOKIE_NAMES:
        value = cookie_values.get(name, "")
        if value == "":
            logger.warning(f"Using empty string for missing cookie: {name}")

        # Set appropriate expiration date based on cookie type
        if name in ["personalization_id", "kdt"]:
            # 1 month expiration for these cookies
            expires = one_month_future
            logger.info(f"Setting {name} cookie to expire in 1 month: {expires}")
        elif name in ["auth_token", "ct0"]:
            # 1 week expiration for these cookies
            expires = one_week_future
            logger.info(f"Setting {name} cookie to expire in 1 week: {expires}")
        else:
            # Default 1 week for all other cookies
            expires = one_week_future
            logger.info(
                f"Setting {name} cookie to default expiration (1 week): {expires}"
            )

        cookies.append(create_cookie_template(name, value, domain, expires))

    return cookies


def is_confirmation_window_visible(driver, timeout=10):
    """Return True if the X.com 'Check your email' window appears."""
    try:
        WebDriverWait(driver, timeout).until(
            EC.presence_of_element_located(
                (By.XPATH, "//h1[contains(translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'check your email')]")
            )
        )
        return True
    except Exception:
        return False

def find_confirmation_input(driver, timeout=10):
    """Find the confirmation code input field if present."""
    selectors = [
        (By.CSS_SELECTOR, 'input[autocomplete="one-time-code"]'),
        (By.NAME, 'text'),
        (By.CSS_SELECTOR, 'input[placeholder*="confirmation" i]'),
        (By.XPATH, "//input[contains(@aria-label, 'code') or contains(@placeholder, 'code')]"),
    ]
    for by, val in selectors:
        try:
            el = WebDriverWait(driver, timeout).until(EC.presence_of_element_located((by, val)))
            return el
        except Exception:
            continue
    return None

def find_visible_element(driver, selectors):
    for sel in selectors:
        try:
            els = driver.find_elements(By.CSS_SELECTOR, sel)
        except Exception:
            els = []
        for el in els:
            try:
                if el.is_displayed():
                    return el
            except Exception:
                continue
    return None

def get_email_and_password_for_index(accindex, password_param=None):
    """
    Return (email, email_password) for the given account index.
    - email is resolved using your existing extract_email_from_password(password, accindex)
      (the caller should pass the account password string it already passes into that function).
    - email_password is read from TWITTER_EMAIL_PASSWORD env var split by '+' (same as extract_gmx_password).
    """
    # email: caller may already compute it; if not, fallback to reading from TWITTER_EMAIL list
    # We accept password_param if provided (like the account password passed into process_account_state_machine)
    try:
        if password_param is not None:
            email_addr = extract_email_from_password(password_param, accindex)
        else:
            # fallback: read first TWITTER_EMAIL entry
            email_list = os.environ.get("TWITTER_EMAIL", "")
            email_addr = email_list.split("+")[accindex] if email_list else None
    except Exception:
        email_addr = None

    # email password list
    pwd_list = os.environ.get("TWITTER_EMAIL_PASSWORD", "")
    email_pwd = None
    if pwd_list:
        parts = pwd_list.split("+")
        if accindex < len(parts):
            email_pwd = parts[accindex]

    return email_addr, email_pwd


def try_fetch_and_apply_confirmation_code(driver, email_addr, accindex, password_param=None):
    """
    If a confirmation code input is visible on the page, try to fetch the X code via IMAP (GMX or Rambler)
    and type it into the input. Returns True if a code was fetched and entered, False otherwise.
    """
    if not email_addr:
        logger.info("[CODE] No email address provided for fetching confirmation code.")
        return False

    # Quick check: is a code input visible?
    code_input = find_confirmation_input(driver)
    if not code_input:
        logger.info("[CODE] No confirmation input detected on page.")
        # nothing to do
        return False

    logger.info("[CODE] Confirmation input detected on page. Attempting to fetch code from email.")

    # Determine which IMAP to try based on email domain
    domain = (email_addr.split("@")[-1] or "").lower()
    # Get email password from env mapping
    _, email_pwd = get_email_and_password_for_index(accindex, password_param)

    code = None

    # Try GMX
    if "gmx." in domain or domain.endswith("gmx.com"):
        if not email_pwd:
            email_pwd = extract_gmx_password(accindex)
        try:
            code = fetch_latest_x_code(email_addr, email_pwd, timeout_sec=TOTAL_TIMEOUT_SEC, poll_interval=POLL_INTERVAL_SEC)
        except Exception as e:
            logger.warning(f"[CODE][GMX] Error fetching code: {e}")

    # Try Rambler
    if (not code) and ("rambler" in domain or domain.endswith("rambler.ru")):
        try:
            if not email_pwd:
                # fallback: same env var used for GMX passwords
                # _, email_pwd = get_email_and_password_for_index(accindex, password_param)
                email_pwd = extract_gmx_password(accindex)
            code = fetch_latest_x_code_rambler(email_addr, email_pwd, timeout_sec=TOTAL_TIMEOUT_SEC, poll_interval=POLL_INTERVAL_SEC)
        except Exception as e:
            logger.warning(f"[CODE][RAMBLER] Error fetching code: {e}")

    # As a last resort, try GMX anyway if code still missing (in case aliasing)
    if not code and "gmx" not in domain:
        try:
            if email_pwd:
                code = fetch_latest_x_code(email_addr, email_pwd, timeout_sec=TOTAL_TIMEOUT_SEC//2, poll_interval=POLL_INTERVAL_SEC)
        except Exception:
            pass

    if not code:
        logger.info("[CODE] No confirmation code found in email within timeout.")
        return False

    logger.info(f"[CODE] Retrieved code: {code} — typing into input.")
    # Use your existing typing method
    success = find_and_fill_input(driver, "code", code)
    if not success:
        # fallback: send keys directly to detected code input
        try:
            driver.execute_script("arguments[0].scrollIntoView({block:'center'});", code_input)
            time.sleep(0.2)
            code_input.click()
            time.sleep(0.2)
            code_input.clear()
            code_input.send_keys(code)
            time.sleep(0.5)
            logger.info("[CODE] Entered code via direct send_keys fallback.")
            return True
        except Exception as e:
            logger.warning(f"[CODE] Fallback typing failed: {e}")
            return False

    return True

def process_account_state_machine(driver, username, password, accindex):
    """Process a Twitter account login flow that may not change URL (SPA-safe)."""
    logger.info(f"==========================================")
    logger.info(f"Starting to process account: {username}")
    output_file = f"{username}_twitter_cookies.json"
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    email = extract_email_from_password(password, accindex)
    logger.info(f"Using email {email} for account {username}")

    # Go to login page
    try:
        driver.get(TWITTER_LOGIN_URL)
        WebDriverWait(driver, 15).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, 'input[name="text"]'))
        )
        logger.info("Twitter login page loaded.")
    except Exception as e:
        logger.error(f"Failed to open Twitter login page: {e}")
        return False

    start_time = time.time()
    last_action_time = start_time
    login_successful = False
    stage = "username"

    def get_stage():
        """Identify which step of the login flow we’re currently in."""
        try:
            if driver.find_elements(By.CSS_SELECTOR, 'input[name="text"]'):
                return "username"
            if driver.find_elements(By.CSS_SELECTOR, 'input[name="password"]'):
                return "password"
            if driver.find_elements(By.CSS_SELECTOR, '[data-testid="tweetButtonInline"]'):
                return "home"
            return "unknown"
        except Exception:
            return "unknown"

    while time.time() - start_time < WAITING_TIME:
        try:
            # Stage detection
            new_stage = get_stage()

            # if is_anti_bot_triggered(driver) or needs_verification(driver):
            #     logger.info("[ANTI-BOT] Detected anti-bot or verification challenge.")
            #     try:
            #         disconnect_vpn()
            #         time.sleep(2)
            #         rotate_server_in_ovpn()
            #         reconnect_vpn()
            #         time.sleep(10)
            #         return False
            #     except Exception as e:
            #         logger.warning(f"[ANTI-BOT] VPN rotation failed: {e}")

            if new_stage != stage:
                logger.info(f"Stage changed: {stage} → {new_stage}")
                stage = new_stage
                last_action_time = time.time()

            # --- 1️⃣ Username step ---
            if stage == "username":
                if find_and_fill_input(driver, "username", username):
                    click_next_button(driver)
                    try:
                        WebDriverWait(driver, 10).until(
                            EC.presence_of_element_located((By.CSS_SELECTOR, 'input[name="password"]'))
                        )
                        stage = "password"
                        rand_sleep(2.1, 3.2)
                        logger.info("Moved to password stage.")
                    except Exception:
                        logger.info("No password field yet (maybe verification).")
                    last_action_time = time.time()

            # --- 2️⃣ Verification (optional) ---
            # elif needs_verification(driver):
            #     logger.info("Verification screen detected.")
            #     find_and_fill_input(driver, "email", email)
            #     click_next_button(driver)
            #     last_action_time = time.time()
            #     time.sleep(2)
            elif needs_verification(driver):
                logger.info("Verification screen detected.")
                find_and_fill_input(driver, "email", email)
                click_next_button(driver)
                last_action_time = time.time()
                time.sleep(2)

                # Attempt to fetch and apply the confirmation code from IMAP (GMX or Rambler)
                try:
                    fetched = try_fetch_and_apply_confirmation_code(driver, email, accindex, password)
                    if fetched:
                        logger.info("[VERIF] Confirmation code applied; continuing.")
                        time.sleep(2)
                        # click next/submit if necessary
                        click_next_button(driver)
                        rand_sleep(1, 2)
                except Exception as e:
                    logger.warning(f"[VERIF] Error while fetching/applying code: {e}")


            # --- 3️⃣ Password step ---
            elif stage == "password":
                if find_and_fill_input(driver, "password", password):
                    click_next_button(driver)
                    # After submitting password, some flows ask for confirmation code
                    # Try to fetch code and apply if input is present
                    logger.info("Submitted password; checking for confirmation code input.")
                    if is_confirmation_window_visible(driver):
                        logger.info("Confirmation window detected.")
                        try:
                            fetched = try_fetch_and_apply_confirmation_code(driver, email, accindex, password)
                            if fetched:
                                logger.info("[PASSWORD->CODE] Confirmation code applied after password submit.")
                                # try to detect home again
                                try:
                                    WebDriverWait(driver, 8).until(
                                        EC.presence_of_element_located((By.CSS_SELECTOR, '[data-testid="tweetButtonInline"]'))
                                    )
                                    stage = "home"
                                    logger.info("Detected tweet button — login success after code.")
                                except Exception:
                                    logger.info("Still waiting for home screen after entering code.")
                        except Exception as e:
                            logger.warning(f"[PASSWORD->CODE] Exception while fetching code: {e}")
                    else:
                        try:
                            WebDriverWait(driver, 15).until(
                                EC.presence_of_element_located(
                                    (By.CSS_SELECTOR, '[data-testid="tweetButtonInline"]')
                                )
                            )
                            stage = "home"
                            logger.info("Detected tweet button — login success.")
                        except Exception:
                            logger.info("Waiting for home screen after password entry.")
                    last_action_time = time.time()
                    rand_sleep(2.1, 3.2)
                    
            # --- 4️⃣ Logged in ---
            elif stage == "home" or is_logged_in(driver):
                logger.info("Login successful; extracting cookies.")
                login_successful = True
                break

            # --- 5️⃣ Idle fallback ---
            elif time.time() - last_action_time > 30:
                logger.info("No progress for 30s — retrying click.")
                click_next_button(driver)
                last_action_time = time.time()

            time.sleep(POLLING_INTERVAL)

        except WebDriverException as e:
            if "no such window" in str(e).lower() or "no such session" in str(e).lower():
                logger.info("Browser closed during login (possibly VPN switch).")
                raise
            logger.warning(f"WebDriverException during loop: {e}")
            time.sleep(3)
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            time.sleep(3)

    # --- 🧁 Finalization ---
    if login_successful:
        try:
            if "home" not in driver.current_url.lower():
                driver.get("https://twitter.com/home")
                time.sleep(3)

            cookie_values, domain = extract_cookies(driver)
            cookies_json = generate_cookies_json(cookie_values, domain)

            output_path = os.path.join(OUTPUT_DIR, output_file)
            with open(output_path, "w") as f:
                f.write(json.dumps(cookies_json, indent=2))
            logger.info(f"Saved cookies for {username} to {output_path}")
            return True

        except Exception as e:
            logger.error(f"Error saving cookies for {username}: {e}")
            return False

    logger.error(f"Login failed for {username} within {WAITING_TIME}s.")
    return False

def main():
    """Main function to process Twitter accounts from environment variable."""
    logger.info("Starting cookie grabber")

    # Check for required environment variables
    if not os.environ.get("TWITTER_EMAIL"):
        logger.error("TWITTER_EMAIL environment variable is not set.")
        logger.error("This is required for email verification during login.")
        return

    # Get Twitter accounts from environment variable
    twitter_accounts_str = os.environ.get("TWITTER_ACCOUNTS", "")

    if not twitter_accounts_str:
        logger.error("TWITTER_ACCOUNTS environment variable is not set.")
        logger.error("Format should be: username1:password1,username2:password2")
        return

    account_pairs = twitter_accounts_str.split(",")
    logger.info(f"Found {len(account_pairs)} accounts to process")
    logger.info(
        "Browser reset between accounts is disabled to reduce verification challenges"
    )

    # Create the output directory if it doesn't exist
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Process accounts one by one
    current_account_index = 0
    failed_account_list = []
    while current_account_index < len(account_pairs):
        # Maximum number of retries for account processing
        max_retries = 1  # Increased retries to allow for VPN switches
        retry_count = 0
        driver = None

        account_pair = account_pairs[current_account_index]
        if ":" not in account_pair:
            logger.error(
                f"Invalid account format: {account_pair}. Expected format: username:password"
            )
            current_account_index += 1
            continue

        username, password = account_pair.split(":", 1)
        username = username.strip()
        password = password.strip()

        logger.info(
            f"Processing account {current_account_index+1}/{len(account_pairs)}: {username}"
        )

        # disconnect_vpn()
        # time.sleep(1)
        # rotate_server_in_ovpn()
        # reconnect_vpn()
        # time.sleep(10)
        # logger.info(f"VPN reconnected. Current IP: {new_ip}")
        
        # Process account with potential window closing for VPN switching
        success = False
        while retry_count < max_retries and not success:
            try:
                # Initialize a new driver for each retry
                if driver is not None:
                    try:
                        driver.quit()
                    except:
                        pass
                
                driver = start_driver_with_proxy() #launch_uc_driver()
                logger.info(
                    f"Browser initialized for account: {username} (attempt {retry_count+1}/{max_retries})"
                )
                logger.info( f"kkkkk3" )
                # Process the current account
                success = process_account_state_machine(driver, username, password, current_account_index)

                if success:
                    logger.info(f"Successfully processed account: {username}")
                else:
                    retry_count += 1
                    logger.info(
                        f"Account processing unsuccessful. Retries left: {max_retries - retry_count}"
                    )
                    time.sleep(10)  # Brief pause before retry

            except WebDriverException as e:
                # Special handling for closed window (VPN switching)
                if (
                    "no such window" in str(e).lower()
                    or "no such session" in str(e).lower()
                ):
                    logger.info(
                        "Browser window was closed. This might be for VPN switching."
                    )
                    logger.info(
                        "Waiting 30 seconds for VPN to stabilize before retrying..."
                    )

                    # Clean up the driver
                    try:
                        if driver:
                            driver.quit()
                    except:
                        pass

                    # Wait for VPN switch to complete
                    time.sleep(30)

                    # Don't increment retry count for intentional window closing
                    # This allows unlimited VPN switches
                    logger.info(f"Resuming after window close for account: {username}")
                else:
                    # Handle other WebDriver exceptions
                    retry_count += 1
                    logger.error(
                        f"WebDriver error (attempt {retry_count}/{max_retries}): {str(e)}"
                    )
                    time.sleep(15)

            except Exception as e:
                retry_count += 1
                logger.error(
                    f"Unexpected error (attempt {retry_count}/{max_retries}): {str(e)}"
                )
                time.sleep(15)

                try:
                    if driver:
                        driver.quit()
                except:
                    pass

        # Clean up the driver
        try:
            if driver:
                driver.quit()
        except:
            pass

        # Move to next account only if successful or max retries reached
        if success or retry_count >= max_retries:
            if success:
                logger.info(f"Successfully completed account: {username}")
            else:
                failed_account_list.append(current_account_index)
                logger.warning(
                    f"Failed to process account after {max_retries} attempts: {username}"
                )

            current_account_index += 1

            # Cooldown between accounts
            if current_account_index < len(account_pairs):
                cool_down = random.uniform(5, 10)  # 5-10 seconds cooldown
                logger.info(
                    f"Cooling down for {cool_down:.1f} seconds before next account"
                )

                time.sleep(cool_down)

    logger.info(f"All accounts processed {len(failed_account_list)}/{len(account_pairs)}")

    logger.info("FAILed accounts:")

    for index in failed_account_list:
        logger.info(account_pairs[index])


if __name__ == "__main__":
    load_dotenv()  # Load environment variables
    logger.info("Starting cookie grabber script")
    main()
