"""The optional e-mail login (conta.js) on the static site: static checks.

The behaviour itself (login dialog, cloud sync of the course and the lab, sign out, delete account) runs in a
browser against Supabase; these tests guard the parts that can break silently: keys, wiring and the schema record.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTA = (ROOT / "conta.js").read_text(encoding="utf-8")


def test_only_the_public_key_is_in_the_site():
    for name in ("conta.js", "admin.js", "index.html", "estudar.html", "privacidade.html"):
        text = (ROOT / name).read_text(encoding="utf-8")
        assert "sb_secret_" not in text and "service_role" not in text, name
    assert re.search(r'SUPABASE_KEY = "sb_publishable_\w+"', CONTA)


def test_the_lab_still_opens_without_conta():
    index = (ROOT / "index.html").read_text(encoding="utf-8")
    # dynamic import inside try: a failed load (offline CDN) must not stop the lab from mounting
    assert 'try { conta = await import("./conta.js"); }' in index
    assert index.index("pullLabBeforeMount") < index.index("mount(\n")
    assert "conta.watchLab()" in index


def test_course_page_wiring():
    page = (ROOT / "estudar.html").read_text(encoding="utf-8")
    assert 'import {mountCourse,cloudLabFiles,courseChanged} from "./conta.js";' in page
    assert 'import {openAdmin} from "./admin.js";' in page and "window.soclabWhere=" in page
    assert "if(window.soclabChanged)window.soclabChanged()" in page  # save() tells conta.js
    assert "window.soclabReload=" in page and "window.soclabCloudLab" in page


def test_lab_files_match_the_stlite_layout():
    index = (ROOT / "index.html").read_text(encoding="utf-8")
    assert 'idbfsMountpoints: ["/mnt"]' in index and 'SOC_LAB_ANSWERS_DIR: "/mnt/soclab"' in index
    assert 'const LAB_DIR = "/mnt/soclab/";' in CONTA
    assert 'indexedDB.open("/mnt", 21)' in CONTA and '"FILE_DATA"' in CONTA


def test_privacy_notice_and_account_deletion():
    privacy = (ROOT / "privacidade.html").read_text(encoding="utf-8")
    for text in ("Estados Unidos", "Apagar minha conta", "LGPD", "UK GDPR"):
        assert text in privacy
    assert 'href="privacidade.html"' in CONTA and 'sb.rpc("delete_my_account")' in CONTA


def test_admin_and_feedback_are_guarded_by_the_server():
    sql = next((ROOT / "supabase" / "migrations").glob("*_admin_and_feedback.sql")).read_text(encoding="utf-8")
    assert "if not public.is_admin() then" in sql  # admin_overview refuses everyone else
    assert 'for select to authenticated using ((select public.is_admin()))' in sql  # only the admin reads feedback
    assert "grant insert (page, context, message, user_id) on public.feedback to anon, authenticated;" in sql
    assert "revoke all on public.admins from anon, authenticated;" in sql
    admin = (ROOT / "admin.js").read_text(encoding="utf-8")
    assert "if (!(await isAdmin()))" in admin and 'from "./conta.js"' in admin


def test_schema_record_has_row_level_security():
    sql = next((ROOT / "supabase" / "migrations").glob("*_progress_and_account_deletion.sql")).read_text(encoding="utf-8")
    assert "enable row level security" in sql
    assert sql.count("(select auth.uid()) = user_id") >= 4
    assert "revoke execute on function public.delete_my_account() from public, anon;" in sql
    assert "on delete cascade" in sql
