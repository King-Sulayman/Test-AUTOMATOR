import argparse
import base64
import binascii
import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import requests

AUTH_TOKEN_URL = "https://services.biselahore.com/Authentication/GetToken/"
RESULT_IMAGE_URL = "https://services.biselahore.com/Download/GetResultImage"

BASE_HEADERS = {
    # Useful for telling the server what we want back
    "Accept": "application/json, text/plain, */*",
    # Sometimes required to mimic the portal
    "Origin": "https://eportal.biselahore.com",
    "Referer": "https://eportal.biselahore.com/",
    # Some servers block requests without a UA
    "User-Agent": "Mozilla/5.0",
}


def _create_session() -> requests.Session:
    """
    Shared session with conservative retries for transient network/server errors.
    """
    s = requests.Session()
    retry = Retry(
        total=5,
        connect=5,
        read=5,
        status=5,
        backoff_factor=0.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "POST"]),
        raise_on_status=False,
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s


def _safe_json_dict(response: requests.Response) -> Dict[str, Any]:
    """
    Parse response as JSON dict with a helpful error if it isn't.
    """
    try:
        data = response.json()
    except ValueError:
        snippet = (response.text or "")[:400]
        raise ValueError(f"Expected JSON but got non-JSON response. status={response.status_code}, body={snippet!r}")
    if not isinstance(data, dict):
        raise ValueError("Unexpected JSON response (not a JSON object).")
    return data


def _jwt_expiry_epoch_seconds(token: str) -> Optional[int]:
    """
    Best-effort parse of JWT exp claim. Returns epoch seconds or None.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload_b64 = parts[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload = base64.urlsafe_b64decode(payload_b64.encode("ascii"))
        obj = json.loads(payload.decode("utf-8"))
        exp = obj.get("exp")
        if isinstance(exp, (int, float)):
            return int(exp)
        if isinstance(exp, str) and exp.isdigit():
            return int(exp)
        return None
    except (ValueError, binascii.Error, UnicodeDecodeError, json.JSONDecodeError):
        return None


class _TokenProvider:
    """
    Caches an anonymous bearer token until near-expiry, and refreshes on demand.
    """

    def __init__(self, session: requests.Session):
        self._session = session
        self._token: Optional[str] = None
        self._exp: Optional[int] = None

    def get(self, timeout: int = 30) -> str:
        now = int(time.time())
        if self._token and self._exp and now < (self._exp - 60):
            return self._token
        return self.refresh(timeout=timeout)

    def refresh(self, timeout: int = 30) -> str:
        token = fetch_anonymous_bearer_token(self._session, timeout=timeout)
        self._token = token
        self._exp = _jwt_expiry_epoch_seconds(token)
        return token


def fetch_anonymous_bearer_token(session: requests.Session, timeout: int = 30) -> str:
    """
    Fetch a fresh anonymous JWT used by the public e-portal (no login).
    Returns the raw token (without the 'Bearer ' prefix).
    """
    token_headers = {
        "Accept": BASE_HEADERS.get("Accept", "application/json, text/plain, */*"),
        "Origin": BASE_HEADERS.get("Origin", "https://eportal.biselahore.com"),
        "Referer": BASE_HEADERS.get("Referer", "https://eportal.biselahore.com/"),
        "User-Agent": BASE_HEADERS.get("User-Agent", "Mozilla/5.0"),
    }
    r = session.get(AUTH_TOKEN_URL, headers=token_headers, timeout=timeout)
    r.raise_for_status()
    data = _safe_json_dict(r)
    token = data.get("AuthToken") or data.get("authToken") or data.get("token")
    if not token or not isinstance(token, str):
        raise ValueError("Token response did not include AuthToken.")
    return token


@dataclass
class StudentResult:
    student: Dict[str, Any]
    pic_path: Optional[str]
    image_bytes: Optional[bytes]
    image_content_type: Optional[str]


def _exam_from_class(student_class: int) -> Tuple[str, int]:
    if student_class == 9:
        return "SSC", 1
    if student_class == 10:
        return "SSC", 2
    if student_class == 11:
        return "HSSC", 1
    if student_class == 12:
        return "HSSC", 2
    raise ValueError("class must be 9, 10, 11, or 12.")


def _request_json_with_401_refresh(
    method: str,
    url: str,
    headers_in: Dict[str, str],
    timeout: int,
    session: requests.Session,
    token_provider: _TokenProvider,
    json_body: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Make a request, and if it returns 401, refresh token and retry once.
    Returns JSON dict.
    """
    hdrs = dict(headers_in)
    if "Authorization" not in hdrs:
        hdrs["Authorization"] = f"Bearer {token_provider.get(timeout=timeout)}"

    def do_request(h: Dict[str, str]) -> requests.Response:
        return session.request(method, url, headers=h, json=json_body, timeout=timeout)

    r = do_request(hdrs)
    if r.status_code == 401:
        hdrs["Authorization"] = f"Bearer {token_provider.refresh(timeout=timeout)}"
        r = do_request(hdrs)
    r.raise_for_status()
    return _safe_json_dict(r)


def fetch_student_with_image(
    roll_number: int,
    student_class: int,
    year: int,
    timeout: int = 30,
    *,
    session: Optional[requests.Session] = None,
    token_provider: Optional[_TokenProvider] = None,
) -> StudentResult:
    """
    Fetch student data + result image using the public anonymous token flow.
    """
    if not (100000 <= roll_number <= 999999):
        raise ValueError("roll_number must be a 6-digit integer.")

    session = session or _create_session()
    token_provider = token_provider or _TokenProvider(session)

    exam_name, exam_part = _exam_from_class(student_class)
    student_url = (
        f"https://services.biselahore.com/Student/GetStudent/"
        f"{roll_number}/{exam_name}/{exam_part}/Annual/{year}"
    )

    # Base headers; Authorization gets injected/refreshed automatically.
    base_headers: Dict[str, str] = dict(BASE_HEADERS)

    student = _request_json_with_401_refresh(
        "GET",
        student_url,
        base_headers,
        timeout=timeout,
        session=session,
        token_provider=token_provider,
    )
    pic_path = student.get("PicPath")

    image_bytes: Optional[bytes] = None
    image_content_type: Optional[str] = None

    if isinstance(pic_path, str) and pic_path.strip():
        img_payload = {"MediaURL": pic_path, "MediaExtension": "image/jpeg"}

        # This endpoint typically returns raw image bytes (binary). In some cases it may
        # return JSON (e.g., base64). We'll only attempt JSON parsing if content-type says so.
        hdrs = dict(base_headers)
        hdrs["Authorization"] = f"Bearer {token_provider.get(timeout=timeout)}"

        r = session.post(RESULT_IMAGE_URL, headers=hdrs, json=img_payload, timeout=timeout)
        if r.status_code == 401:
            hdrs["Authorization"] = f"Bearer {token_provider.refresh(timeout=timeout)}"
            r = session.post(RESULT_IMAGE_URL, headers=hdrs, json=img_payload, timeout=timeout)
        r.raise_for_status()

        image_content_type = r.headers.get("Content-Type")
        if image_content_type and "application/json" in image_content_type.lower():
            j = _safe_json_dict(r)
            # Common patterns: base64 in data/result/fileBytes/etc.
            b64 = None
            if isinstance(j, dict):
                for k in ("FileBytes", "fileBytes", "ImageBytes", "imageBytes", "Data", "data", "Result", "result"):
                    if isinstance(j.get(k), str):
                        b64 = j.get(k)
                        break
            if b64:
                image_bytes = base64.b64decode(b64)
        else:
            # Binary image payload
            image_bytes = r.content

    return StudentResult(
        student=student,
        pic_path=pic_path if isinstance(pic_path, str) else None,
        image_bytes=image_bytes,
        image_content_type=image_content_type,
    )


def _class_db_filename(year: int, student_class: int) -> str:
    if student_class not in (9, 10, 11, 12):
        raise ValueError("class must be 9, 10, 11, or 12.")
    suffix = {9: "9th", 10: "10th", 11: "11th", 12: "12th"}[student_class]
    return f"{year}_{suffix}.db"


def init_results_db(db_path: str) -> None:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS students (
                RollNo INTEGER PRIMARY KEY,
                Name TEXT NOT NULL,
                FatherName TEXT NULL,
                DOB TEXT NULL,
                Cnic TEXT NULL,
                FatherCnic TEXT NULL,
                RegistrationNo TEXT NULL,
                AppearedAs TEXT NULL,
                Institute TEXT NULL,
                PicPath TEXT NULL,
                Gender TEXT NULL,
                MarksObtained INTEGER NULL,
                PassStatus TEXT NULL,
                Photo BLOB NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_students_cnic ON students(Cnic)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_students_father_cnic ON students(FatherCnic)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_students_name ON students(Name)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_students_father_name ON students(FatherName)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_students_institute ON students(Institute)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_students_registration_no ON students(RegistrationNo)")


def save_result_to_db(db_path: str, roll_number: int, result: StudentResult) -> None:
    s = result.student or {}

    def _none_if_blank(v: Any) -> Any:
        if v is None:
            return None
        if isinstance(v, str) and not v.strip():
            return None
        return v

    row = {
        "RollNo": roll_number,
        "Name": _none_if_blank(s.get("Name")),
        "FatherName": _none_if_blank(s.get("FatherName")),
        "DOB": _none_if_blank(s.get("DOB")),
        "Cnic": _none_if_blank(s.get("CandidateCnic")),
        "FatherCnic": _none_if_blank(s.get("FatherCnic")),
        "RegistrationNo": _none_if_blank(s.get("RegistrationNo")),
        "AppearedAs": _none_if_blank(s.get("AppearedAs")),
        "Institute": _none_if_blank(s.get("AppearedFrom")),
        "PicPath": _none_if_blank(s.get("PicPath")),
        "Gender": _none_if_blank(s.get("Gender")),
        "MarksObtained": _none_if_blank(s.get("MarksObtained")),
        "PassStatus": _none_if_blank(s.get("PassStatus")),
        "Photo": result.image_bytes,
    }

    if not row["Name"]:
        raise ValueError("Student Name is missing; cannot store (Name is NOT NULL).")

    init_results_db(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute(
            """
            INSERT INTO students (
                RollNo, Name, FatherName, DOB, Cnic, FatherCnic, RegistrationNo,
                AppearedAs, Institute, PicPath, Gender, MarksObtained, PassStatus, Photo
            )
            VALUES (
                :RollNo, :Name, :FatherName, :DOB, :Cnic, :FatherCnic, :RegistrationNo,
                :AppearedAs, :Institute, :PicPath, :Gender, :MarksObtained, :PassStatus, :Photo
            )
            ON CONFLICT(RollNo) DO UPDATE SET
                Name=excluded.Name,
                FatherName=excluded.FatherName,
                DOB=excluded.DOB,
                Cnic=excluded.Cnic,
                FatherCnic=excluded.FatherCnic,
                RegistrationNo=excluded.RegistrationNo,
                AppearedAs=excluded.AppearedAs,
                Institute=excluded.Institute,
                PicPath=excluded.PicPath,
                Gender=excluded.Gender,
                MarksObtained=excluded.MarksObtained,
                PassStatus=excluded.PassStatus,
                Photo=excluded.Photo
            """
            ,
            row,
        )


def roll_exists_in_db(db_path: str, roll_number: int) -> bool:
    """
    Returns True if a record for roll_number already exists in the DB.
    If the DB/table isn't available for any reason, returns False (so the caller can fetch).
    """
    try:
        with sqlite3.connect(db_path) as conn:
            conn.execute("PRAGMA busy_timeout = 5000")
            cur = conn.execute("SELECT 1 FROM students WHERE RollNo = ? LIMIT 1", (roll_number,))
            return cur.fetchone() is not None
    except Exception:
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch student records and store them in a SQLite DB.")
    parser.add_argument("--start-roll", type=int, required=True, help="Starting 6-digit roll number (inclusive).")
    parser.add_argument("--end-roll", type=int, required=True, help="Ending 6-digit roll number (inclusive).")
    parser.add_argument("--class", dest="student_class", type=int, required=True, help="9, 10, 11, or 12.")
    parser.add_argument("--year", type=int, required=True, help="Exam year, e.g. 2019.")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds.")
    parser.add_argument(
        "--skip-existing",
        action="store_true",
        help="If set, skip roll numbers that already exist in the DB (by primary key).",
    )

    # argparse already handles bad CLI input by printing help and exiting.
    args = parser.parse_args()

    # Never stop for this common mistake; just fix it.
    start_roll = args.start_roll
    end_roll = args.end_roll
    if start_roll > end_roll:
        print("Warning: start-roll > end-roll; swapping them.")
        start_roll, end_roll = end_roll, start_roll

    try:
        db_file = _class_db_filename(args.year, args.student_class)
        init_results_db(db_file)
    except Exception as e:
        print(f"Fatal: could not initialize database: {e}")
        return 1

    total = end_roll - start_roll + 1
    ok = 0
    failed = 0
    skipped = 0

    session = _create_session()
    token_provider = _TokenProvider(session)

    for idx, roll_no in enumerate(range(start_roll, end_roll + 1), start=1):
        try:
            if args.skip_existing and roll_exists_in_db(db_file, roll_no):
                skipped += 1
                print(f"[{idx}/{total}] skipped roll={roll_no} (already in DB)")
                continue
            result = fetch_student_with_image(
                roll_no,
                args.student_class,
                args.year,
                timeout=args.timeout,
                session=session,
                token_provider=token_provider,
            )
            save_result_to_db(db_file, roll_no, result)
            ok += 1
            print(f"[{idx}/{total}] saved roll={roll_no}")
        except KeyboardInterrupt:
            print("\nInterrupted by user. Stopping.")
            break
        except Exception as e:
            failed += 1
            print(f"[{idx}/{total}] failed roll={roll_no}: {e}")

    print(f"Done. saved={ok}, failed={failed}, skipped={skipped}, db={db_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

