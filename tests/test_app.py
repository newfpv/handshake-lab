import io
import csv
import base64
import tempfile
import unittest
import subprocess
import sys
from pathlib import Path
from unittest import mock

import app as audit


SAMPLE = "WPA*01*00112233445566778899aabbccddeeff*001122334455*aabbccddeeff*546573744e6574***00\n"


class AuditAppTests(unittest.TestCase):
    def setUp(self):
        audit.runner.stop_event.set()
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        audit.DB_PATH = root / "test.db"
        audit.CONFIG_PATH = root / "config.json"
        audit.RESULTS_CSV = root / "recovered.csv"
        audit.POTFILE = root / "test.potfile"
        audit.init_storage()
        audit.app.config.update(TESTING=True)
        self.client = audit.app.test_client()
        self.created_paths = []

    def tearDown(self):
        for path in self.created_paths:
            Path(path).unlink(missing_ok=True)
        self.temp.cleanup()

    def test_parse_22000(self):
        path = Path(self.temp.name) / "sample.22000"
        path.write_text(SAMPLE, encoding="utf-8")
        parsed = audit.parse_22000(path)
        self.assertEqual(parsed[0]["essid"], "TestNet")
        self.assertEqual(parsed[0]["bssid"], "001122334455")

    def test_telegram_pcap_document_uses_capture_import_pipeline(self):
        with mock.patch.object(audit, "upload_captures") as handler:
            handler.side_effect = lambda: (
                audit.jsonify({"imported": [{"filename": "sample.PCAP", "networks": 1, "status": "ready"}], "errors": []}),
                200,
            )
            status, result = audit.import_telegram_document("sample.PCAP", b"pcap payload")
        self.assertEqual(status, 200)
        self.assertEqual(result["imported"][0]["status"], "ready")
        handler.assert_called_once_with()

    def test_telegram_panel_has_controls_and_https_web_app(self):
        config = audit.load_config()
        config.update({
            "queue_paused": False,
            "workload_profile": 3,
            "remote_access_enabled": True,
            "remote_https_url": "https://lab.example.com",
        })
        audit.atomic_json(audit.CONFIG_PATH, config)
        keyboard = audit.telegram_keyboard(config)
        buttons = [button for row in keyboard["inline_keyboard"] for button in row]
        callbacks = {button.get("callback_data") for button in buttons}
        self.assertTrue({"hl:status", "hl:queue", "hl:toggle", "hl:results", "hl:upload", "hl:help"}.issubset(callbacks))
        self.assertTrue({"hl:w1", "hl:w2", "hl:w3", "hl:w4"}.issubset(callbacks))
        web_button = next(button for button in buttons if "web_app" in button)
        self.assertEqual(web_button["web_app"]["url"], "https://lab.example.com")

    def test_remote_web_app_rejects_plain_http_url(self):
        response = self.client.put("/api/config", json={"remote_https_url": "http://lab.example.com"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("HTTPS", response.get_json()["error"])

    def test_self_signed_https_url_is_used_only_when_explicitly_enabled(self):
        original_url = audit.SELF_SIGNED_HTTPS_URL
        try:
            audit.SELF_SIGNED_HTTPS_URL = "https://203.0.113.4:8788"
            config = audit.load_config()
            config.update({"remote_access_enabled": True, "self_signed_https_enabled": True, "remote_https_url": ""})
            self.assertEqual(audit.telegram_https_url(config), "https://203.0.113.4:8788")
            config["self_signed_https_enabled"] = False
            self.assertEqual(audit.telegram_https_url(config), "")
        finally:
            audit.SELF_SIGNED_HTTPS_URL = original_url

    def test_http_and_https_listener_ports_must_differ(self):
        response = self.client.put("/api/config", json={"port": 8788, "https_port": 8788, "self_signed_https_enabled": True})
        self.assertEqual(response.status_code, 400)
        self.assertIn("different port", response.get_json()["error"])

    def test_common_candidates_are_ranked_and_capture_specific(self):
        path = Path(self.temp.name) / "common.22000"
        path.write_text(SAMPLE, encoding="utf-8")
        original_data = audit.DATA
        try:
            audit.DATA = Path(self.temp.name) / "data"
            (audit.DATA / "runtime").mkdir(parents=True)
            generated = audit.common_candidate_wordlist(path, 77)
            candidates = generated.read_text(encoding="utf-8").splitlines()
        finally:
            audit.DATA = original_data
        self.assertEqual(candidates[:4], ["12345678", "password", "123456789", "qwerty123"])
        self.assertIn("TestNet1234", candidates)
        self.assertIn("22334455", candidates)
        self.assertEqual(len(candidates), len(set(candidates)))

    def test_wordlist_analyzer_streams_wpa_lengths_and_duplicates(self):
        path = Path(self.temp.name) / "candidates.txt"
        path.write_bytes(b"tiny\npassword\npassword\n" + b"x" * 64 + b"\n1234567\x00\n\n")
        original_data = audit.DATA
        try:
            audit.DATA = Path(self.temp.name) / "analysis-data"
            result = audit.analyze_wordlist_file(path)
        finally:
            audit.DATA = original_data
        self.assertEqual(result["lines"], 6)
        self.assertEqual(result["valid"], 2)
        self.assertEqual(result["unique_valid"], 1)
        self.assertEqual(result["duplicates"], 1)
        self.assertEqual(result["short"], 2)
        self.assertEqual(result["too_long"], 1)
        self.assertEqual(result["nul_bytes"], 1)
        self.assertEqual(result["status"], "complete")

    def test_error_doctor_reports_and_relinks_missing_source(self):
        missing = Path(self.temp.name) / "gone" / "local.dict"
        replacement = audit.ROOT / "wordlists" / "doctor-test.dict"
        replacement.write_text("password123\n", encoding="utf-8")
        self.created_paths.append(replacement)
        with audit.db() as connection:
            connection.execute(
                "INSERT INTO wordlists(filename,stored_path,kind,bytes,sha256,imported_at,position) VALUES(?,?,?,?,?,?,?)",
                (replacement.name, str(missing), "wordlist", 12, "doctor-missing", audit.now(), 999),
            )
        report = audit.error_doctor_report()
        self.assertIn("missing_sources", {item["id"] for item in report["issues"]})
        self.assertEqual(audit.relink_missing_sources(), 1)
        with audit.db() as connection:
            stored = connection.execute("SELECT stored_path FROM wordlists WHERE sha256!='doctor-missing' AND filename=?", (replacement.name,)).fetchone()
            linked = connection.execute("SELECT stored_path FROM wordlists WHERE filename=? ORDER BY id DESC", (replacement.name,)).fetchone()
        self.assertIsNotNone(linked)
        self.assertTrue(Path(linked[0]).is_file())

    def test_pattern_builder_learns_local_results_and_changes_fingerprint(self):
        path = Path(self.temp.name) / "pattern.22000"
        path.write_text(SAMPLE, encoding="utf-8")
        audit.append_result("OldRouter", "AABBCCDDEEFF", "Family2026", None, "Imported")
        original_data = audit.DATA
        try:
            audit.DATA = Path(self.temp.name) / "pattern-data"
            (audit.DATA / "runtime").mkdir(parents=True)
            generated = audit.pattern_candidate_wordlist(path, 78)
            candidates = generated.read_text(encoding="utf-8").splitlines()
            with audit.db() as connection:
                stage = dict(connection.execute("SELECT * FROM strategies WHERE mode='pattern'").fetchone())
                first = audit.strategy_attempt_descriptor(connection, stage)[0]
            audit.append_result("Second", "112233445566", "Office1234", None, "Imported")
            with audit.db() as connection:
                second = audit.strategy_attempt_descriptor(connection, stage)[0]
        finally:
            audit.DATA = original_data
        self.assertIn("Family2026", candidates)
        self.assertIn("TestNet2026", candidates)
        self.assertNotEqual(first, second)

    def test_capture_quality_never_marks_a_valid_hash_unusable(self):
        diagnostic = Path(self.temp.name) / "capture.log"
        diagnostic.write_text("packet read error\nmissing EAPOL M3 frames\nDuration was a way too short", encoding="utf-8")
        valid = audit.capture_quality_assessment({"diagnostic_path": str(diagnostic)}, audit.parse_22000(self._sample_path()))
        empty = audit.capture_quality_assessment({"diagnostic_path": str(diagnostic)}, [])
        self.assertNotEqual(valid["label"], "Unusable")
        self.assertGreater(valid["score"], 0)
        self.assertEqual(empty["label"], "Unusable")

    def test_lan_worker_requires_token_and_registers_persistently(self):
        saved = self.client.put("/api/config", json={"lan_enabled": True, "lan_token": "test-lan-token"})
        self.assertEqual(saved.status_code, 200)
        denied = self.client.post("/api/lan/register", json={"name": "pc-2"})
        self.assertEqual(denied.status_code, 401)
        accepted = self.client.post("/api/lan/register", json={"name": "pc-2", "gpu_name": "RTX test"},
            headers={"Authorization": "Bearer test-lan-token"})
        self.assertEqual(accepted.status_code, 200)
        with audit.db() as connection:
            worker = connection.execute("SELECT name,gpu_name,status FROM lan_workers").fetchone()
        self.assertEqual(tuple(worker), ("pc-2", "RTX test", "idle"))

    def test_public_web_requires_configured_basic_auth(self):
        saved = self.client.put("/api/config", json={
            "remote_access_enabled": True, "remote_username": "owner", "remote_password": "correct-horse-123"
        })
        self.assertEqual(saved.status_code, 200)
        denied = self.client.get("/api/state", environ_base={"REMOTE_ADDR": "8.8.8.8"})
        self.assertEqual(denied.status_code, 401)
        credentials = base64.b64encode(b"owner:correct-horse-123").decode("ascii")
        allowed = self.client.get("/api/state", headers={"Authorization": f"Basic {credentials}"},
                                  environ_base={"REMOTE_ADDR": "8.8.8.8"})
        self.assertEqual(allowed.status_code, 200)
        self.assertNotIn("remote_password_hash", allowed.get_json()["config"])

    def test_public_browser_uses_branded_session_login(self):
        saved = self.client.put("/api/config", json={
            "remote_access_enabled": True, "remote_username": "owner", "remote_password": "correct-horse-123"
        })
        self.assertEqual(saved.status_code, 200)
        redirected = self.client.get("/", environ_base={"REMOTE_ADDR": "8.8.8.8"})
        self.assertEqual(redirected.status_code, 302)
        self.assertIn("/login", redirected.headers["Location"])
        login_page = self.client.get("/login", environ_base={"REMOTE_ADDR": "8.8.8.8"})
        self.assertIn("YOUR QUEUE", login_page.get_data(as_text=True))
        accepted = self.client.post("/login", data={
            "username": "owner", "password": "correct-horse-123", "next": "/"
        }, environ_base={"REMOTE_ADDR": "8.8.8.8"})
        self.assertEqual(accepted.status_code, 302)
        panel = self.client.get("/", environ_base={"REMOTE_ADDR": "8.8.8.8"})
        self.assertEqual(panel.status_code, 200)
        self.assertIn("Sign out", panel.get_data(as_text=True))

    def test_lan_worker_reports_idle_telemetry(self):
        self.client.put("/api/config", json={"lan_enabled": True, "lan_token": "test-lan-token"})
        headers = {"Authorization": "Bearer test-lan-token"}
        self.client.post("/api/lan/register", json={"name": "pc-2", "gpu_name": "RTX test"}, headers=headers)
        claimed = self.client.post("/api/lan/claim", json={
            "name": "pc-2",
            "telemetry": {"temperature": 55, "utilization": 8, "memory_used": 1024, "memory_total": 8192},
        }, headers=headers)
        self.assertEqual(claimed.status_code, 200)
        with audit.db() as connection:
            telemetry = audit.row_dict(connection.execute("SELECT telemetry_json FROM lan_workers WHERE name='pc-2'").fetchone())["telemetry"]
        self.assertEqual(telemetry["temperature"], 55)
        self.assertEqual(telemetry["memory_total"], 8192)
        self.assertIn("sampled_at", telemetry)

    def test_missing_lan_source_requeues_job_and_pauses_worker(self):
        self.client.put("/api/config", json={"lan_enabled": True, "lan_token": "test-lan-token"})
        capture_path = Path(self.temp.name) / "lan-source.22000"
        capture_path.write_text(SAMPLE, encoding="utf-8")
        with audit.db() as connection:
            capture_id = connection.execute(
                """INSERT INTO captures(filename,stored_path,hash_path,kind,networks,status,sha256,imported_at)
                   VALUES('lan-source.22000',?,?,'22000',1,'ready','lan-source-sha',?)""",
                (str(capture_path), str(capture_path), audit.now()),
            ).lastrowid
            strategy_id = connection.execute("SELECT id FROM strategies WHERE mode='dictionary' LIMIT 1").fetchone()[0]
            job_id = connection.execute(
                """INSERT INTO jobs(capture_id,strategy_id,status,session_name,created_at,worker_name)
                   VALUES(?,?,'lan_preparing','lan-source-test',?,'pc-2')""",
                (capture_id, strategy_id, audit.now()),
            ).lastrowid
            connection.execute(
                """INSERT INTO lan_workers(name,status,current_job_id,last_seen,created_at)
                   VALUES('pc-2','running',?,?,?)""",
                (job_id, audit.now(), audit.now()),
            )
        response = self.client.post(
            f"/api/lan/jobs/{job_id}/complete",
            json={
                "name": "pc-2", "exit_code": 2, "outfile": "",
                "log": "Worker preparation failed: Source not found on worker: huge.txt (123 bytes)",
            },
            headers={"Authorization": "Bearer test-lan-token"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["deferred"])
        with audit.db() as connection:
            job = connection.execute("SELECT status,worker_name,finished_at,error FROM jobs WHERE id=?", (job_id,)).fetchone()
            worker = connection.execute("SELECT paused,status,current_job_id FROM lan_workers WHERE name='pc-2'").fetchone()
        self.assertEqual(job["status"], "queued")
        self.assertEqual(job["worker_name"], "")
        self.assertIsNone(job["finished_at"])
        self.assertIn("Source not found", job["error"])
        self.assertEqual(tuple(worker), (1, "idle", None))

    def test_retry_resets_failed_lan_job_without_stale_worker_state(self):
        capture_path = Path(self.temp.name) / "retry.22000"
        capture_path.write_text(SAMPLE, encoding="utf-8")
        with audit.db() as connection:
            capture_id = connection.execute(
                """INSERT INTO captures(filename,stored_path,hash_path,kind,networks,status,sha256,imported_at)
                   VALUES('retry.22000',?,?,'22000',1,'ready','retry-sha',?)""",
                (str(capture_path), str(capture_path), audit.now()),
            ).lastrowid
            strategy_id = connection.execute("SELECT id FROM strategies ORDER BY id LIMIT 1").fetchone()[0]
            job_id = connection.execute(
                """INSERT INTO jobs(capture_id,strategy_id,status,progress,speed,eta,session_name,error,created_at,
                   started_at,finished_at,worker_name,remote_command,recovered,candidates_done,candidates_total)
                   VALUES(?,?,'failed',72,'99 kH/s','soon','retry-test','old error',?,?,?,?,?,1,100,200)""",
                (capture_id, strategy_id, audit.now(), audit.now(), audit.now(), "pc-2", "pause"),
            ).lastrowid
        response = self.client.post(f"/api/jobs/{job_id}/retry")
        self.assertEqual(response.status_code, 200)
        with audit.db() as connection:
            job = connection.execute(
                "SELECT status,progress,speed,eta,error,worker_name,remote_command,recovered,candidates_done,candidates_total FROM jobs WHERE id=?",
                (job_id,),
            ).fetchone()
        self.assertEqual(tuple(job), ("queued", 0.0, "", "", "", "", "", 0, 0, 0))

    def test_job_elapsed_clock_counts_only_active_task_time(self):
        capture_path = Path(self.temp.name) / "elapsed.22000"
        capture_path.write_text(SAMPLE, encoding="utf-8")
        with audit.db() as connection:
            capture_id = connection.execute(
                """INSERT INTO captures(filename,stored_path,hash_path,kind,networks,status,sha256,imported_at)
                   VALUES('elapsed.22000',?,?,'22000',1,'ready','elapsed-sha',?)""",
                (str(capture_path), str(capture_path), audit.now()),
            ).lastrowid
            strategy_id = connection.execute("SELECT id FROM strategies ORDER BY id LIMIT 1").fetchone()[0]
            job_id = connection.execute(
                """INSERT INTO jobs(capture_id,strategy_id,status,session_name,created_at,elapsed_seconds)
                   VALUES(?,?,'queued','elapsed-test',?,10)""",
                (capture_id, strategy_id, audit.now()),
            ).lastrowid
            audit.start_job_clock(connection, job_id, "2026-07-20T10:00:00+00:00")
            audit.stop_job_clock(connection, job_id, "2026-07-20T10:00:05+00:00")
            audit.start_job_clock(connection, job_id, "2026-07-20T11:00:00+00:00")
            audit.stop_job_clock(connection, job_id, "2026-07-20T11:00:03+00:00")
            row = connection.execute(
                "SELECT started_at,active_started_at,elapsed_seconds FROM jobs WHERE id=?", (job_id,)
            ).fetchone()
        self.assertEqual(row["started_at"], "2026-07-20T10:00:00+00:00")
        self.assertIsNone(row["active_started_at"])
        self.assertEqual(row["elapsed_seconds"], 18)

    def test_queue_method_detail_names_sources_masks_and_rules(self):
        sources = {
            7: {"filename": "weakpass.txt"},
            8: {"filename": "best64.rule"},
        }
        dictionary = audit.strategy_method_detail({"mode": "dictionary", "config": {"wordlist_id": 7}}, sources)
        rules = audit.strategy_method_detail({"mode": "rules", "config": {"wordlist_id": 7, "rule_id": 8}}, sources)
        mask = audit.strategy_method_detail({"mode": "mask", "config": {"mask": "?d?d?d?d?d?d?d?d", "increment": True}}, sources)
        self.assertEqual(dictionary, "Dictionary · weakpass.txt")
        self.assertIn("weakpass.txt · Rule · best64.rule", rules)
        self.assertEqual(mask, "Mask · ?d?d?d?d?d?d?d?d · Increment enabled")

    def test_os_level_process_pause_and_resume(self):
        process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            self.assertTrue(audit.set_process_suspended(process, True))
            self.assertIsNone(process.poll())
            self.assertTrue(audit.set_process_suspended(process, False))
            self.assertIsNone(process.poll())
        finally:
            process.terminate()
            process.wait(timeout=5)

    def test_cpu_profile_is_persistent_even_when_only_lan_worker_has_cpu(self):
        response = self.client.put("/api/queue/cpu-profile", json={"profile": "balanced"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(audit.load_config()["cpu_profile"], "balanced")

    def _sample_path(self):
        path = Path(self.temp.name) / "quality.22000"
        path.write_text(SAMPLE, encoding="utf-8")
        return path

    def test_likely_fastest_prioritizes_factory_and_simple_ssids(self):
        factory = Path(self.temp.name) / "factory.22000"
        custom = Path(self.temp.name) / "custom.22000"
        factory_parts = SAMPLE.strip().split("*")
        factory_parts[5] = "54504c696e6b41384533"  # TPLinkA8E3
        factory.write_text("*".join(factory_parts) + "\n", encoding="utf-8")
        custom_parts = SAMPLE.strip().split("*")
        custom_parts[5] = "436166655a616476696e6965"  # CafeZadvinie
        custom.write_text("*".join(custom_parts) + "\n", encoding="utf-8")
        captures = [
            {"id": 1, "filename": "custom", "hash_path": str(custom), "networks": 1},
            {"id": 2, "filename": "factory", "hash_path": str(factory), "networks": 1},
        ]
        ordered = audit.sort_captures(captures, "likely_fastest")
        self.assertEqual([item["id"] for item in ordered], [2, 1])

    def test_workspace_paths_relocate_after_portable_move(self):
        old_root = r"C:\Old\HandshakeLab"
        original = old_root + r"\captures\sample.pcap"
        expected = str(audit.ROOT / "captures" / "sample.pcap")
        self.assertEqual(audit.relocated_workspace_path(original, old_root), expected)
        external = r"D:\Dictionaries\weakpass.txt"
        self.assertEqual(audit.relocated_workspace_path(external, old_root), external)

    def test_converter_output_is_summarized_for_capture_cards(self):
        raw = "Information: missing EAPOL M3 frames!\nInformation: no hashes written to hash files"
        summary = audit.summarize_conversion_output(raw)
        self.assertIn("No usable WPA handshake or PMKID", summary)
        self.assertIn("EAPOL frames are missing", summary)
        self.assertNotIn("Information:", summary)

    def test_hashcat_712_legacy_wpa_outfile_is_imported(self):
        hash_path = Path(self.temp.name) / "legacy.22000"
        outfile = Path(self.temp.name) / "legacy-found.txt"
        hash_path.write_text(SAMPLE, encoding="utf-8")
        outfile.write_text("deadbeef:001122334455:aabbccddeeff:TestNet|password123\n", encoding="utf-8")
        imported, recovered = audit.import_outfile(outfile, 7, "Mask", hash_path, job_id=42)
        self.assertEqual(imported, 1)
        self.assertEqual(recovered, {("TestNet", "001122334455")})
        with audit.db() as connection:
            row = connection.execute("SELECT essid,bssid,password,capture_id,job_id FROM results").fetchone()
        self.assertEqual(tuple(row), ("TestNet", "001122334455", "password123", 7, 42))

    def test_results_export_matches_ohc_and_pwmenu_import_shape(self):
        audit.append_result("TestNet", "001122334455", "password123", None, "Dictionary")
        response = self.client.get("/api/results/export")
        self.assertEqual(response.status_code, 200)
        self.assertIn("filename=recovered.csv", response.headers["Content-Disposition"])
        rows = list(csv.DictReader(io.StringIO(response.data.decode("utf-8-sig"))))
        self.assertEqual(list(rows[0]), ["datetime", "task", "algorithm", "status", "password", "note"])
        self.assertEqual(rows[0]["algorithm"], "WPA(2)")
        self.assertEqual(rows[0]["status"], "FOUND")
        self.assertEqual(rows[0]["password"], "password123")
        plain_task = rows[0]["task"].replace('<br><span class="small">', "").replace("</span>", "")
        self.assertEqual(plain_task[-17:], "00:11:22:33:44:55")
        self.assertEqual(plain_task[:-17], "TestNet")

    def test_recovered_network_is_removed_before_next_stage(self):
        hash_path = Path(self.temp.name) / "already-known.22000"
        hash_path.write_text(SAMPLE, encoding="utf-8")
        with audit.db() as connection:
            connection.execute(
                """INSERT INTO captures(id,filename,stored_path,hash_path,kind,networks,status,note,sha256,imported_at)
                   VALUES(7,'known.22000',?,?, '22000',1,'ready','','known-digest',?)""",
                (str(hash_path), str(hash_path), audit.now()),
            )
        audit.append_result("TestNet", "001122334455", "password123", 7, "Manual verification")
        runtime_hash, _, remaining = audit.prepare_job_hashes({
            "id": 91, "capture_id": 7, "capture_ids_json": "[7]", "mode": "dictionary",
        })
        self.assertIsNone(runtime_hash)
        self.assertEqual(remaining, 0)

    def test_fully_recovered_capture_is_not_queued_again(self):
        hash_path = Path(self.temp.name) / "recovered.22000"
        hash_path.write_text(SAMPLE, encoding="utf-8")
        with audit.db() as connection:
            cursor = connection.execute(
                """INSERT INTO captures(filename,stored_path,hash_path,kind,networks,status,note,sha256,imported_at)
                   VALUES('recovered.22000',?,?,'22000',1,'ready','','recovered-digest',?)""",
                (str(hash_path), str(hash_path), audit.now()),
            )
            capture_id = cursor.lastrowid
            strategy_id = connection.execute("SELECT id FROM strategies WHERE mode='known'").fetchone()[0]
        audit.append_result("TestNet", "001122334455", "password123", capture_id, "Manual verification")

        state = self.client.get("/api/state").get_json()
        capture = next(item for item in state["captures"] if item["id"] == capture_id)
        self.assertTrue(capture["fully_recovered"])
        self.assertEqual(capture["unresolved_networks"], 0)
        queued = self.client.post("/api/queue", json={"capture_ids": [capture_id], "strategy_ids": [strategy_id]})
        self.assertEqual(queued.status_code, 400)
        self.assertIn("already recovered", queued.get_json()["error"])
        with audit.db() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0], 0)

    def test_strategy_order_is_saved_atomically(self):
        with audit.db() as connection:
            original = [row[0] for row in connection.execute("SELECT id FROM strategies WHERE hidden=0 ORDER BY position,id")]
        reordered = list(reversed(original))
        response = self.client.put("/api/strategies/order", json={"strategy_ids": reordered})
        self.assertEqual(response.status_code, 200)
        with audit.db() as connection:
            saved = [row[0] for row in connection.execute("SELECT id FROM strategies WHERE hidden=0 ORDER BY position,id")]
        self.assertEqual(saved, reordered)

    def test_queue_order_and_delete(self):
        with audit.db() as connection:
            connection.execute(
                """INSERT INTO captures(id,filename,stored_path,hash_path,kind,networks,status,note,sha256,imported_at)
                   VALUES(1,'queue.22000','queue.22000','queue.22000','22000',1,'ready','','queue-digest',?)""",
                (audit.now(),),
            )
            strategy_id = connection.execute("SELECT id FROM strategies WHERE mode='known'").fetchone()[0]
            for job_id in (1, 2, 3):
                connection.execute(
                    "INSERT INTO jobs(id,capture_id,strategy_id,status,session_name,created_at,position) VALUES(?,?,?,'queued',?,?,?)",
                    (job_id, 1, strategy_id, f"queue-{job_id}", audit.now(), job_id),
                )
        response = self.client.put("/api/jobs/order", json={"job_ids": [3, 1, 2]})
        self.assertEqual(response.status_code, 200)
        with audit.db() as connection:
            saved = [row[0] for row in connection.execute("SELECT id FROM jobs WHERE status='queued' ORDER BY position,id")]
        self.assertEqual(saved, [3, 1, 2])
        deleted = self.client.delete("/api/jobs/1")
        self.assertEqual(deleted.status_code, 200)
        with audit.db() as connection:
            self.assertIsNone(connection.execute("SELECT id FROM jobs WHERE id=1").fetchone())

    def test_hashcat_712_command_uses_supported_restore_options(self):
        command = audit.runner.build_command({
            "session_name": "command-test",
            "hash_path": str(Path(self.temp.name) / "capture.22000"),
            "config_json": '{"mask":"?d?d?d?d?d?d?d?d"}',
            "workload": 2,
            "mode": "mask",
        }, Path(self.temp.name) / "found.txt")
        self.assertNotIn("--restore-timer", command)
        self.assertIn("--restore-file-path", command)
        self.assertEqual(command[command.index("--workload-profile") + 1], "4")

    def test_global_queue_pause_and_workload_are_persistent(self):
        with audit.db() as connection:
            connection.execute(
                """INSERT INTO captures(id,filename,stored_path,hash_path,kind,networks,status,note,sha256,imported_at)
                   VALUES(1,'profile.22000','profile.22000','profile.22000','22000',1,'ready','','profile-digest',?)""",
                (audit.now(),),
            )
            strategy_id = connection.execute("SELECT id FROM strategies WHERE mode='mask'").fetchone()[0]
            connection.execute(
                "INSERT INTO jobs(id,capture_id,strategy_id,status,session_name,created_at,workload) VALUES(1,1,?,'queued','profile-test',?,3)",
                (strategy_id, audit.now()),
            )
        paused = self.client.post("/api/queue/pause-all")
        self.assertEqual(paused.status_code, 200)
        self.assertTrue(audit.load_config()["queue_paused"])
        changed = self.client.put("/api/queue/workload", json={"workload": 2})
        self.assertEqual(changed.status_code, 200)
        self.assertEqual(changed.get_json()["workload"], 2)
        with audit.db() as connection:
            self.assertEqual(connection.execute("SELECT workload FROM jobs WHERE id=1").fetchone()[0], 2)
        self.assertEqual(audit.load_config()["workload_profile"], 2)
        resumed = self.client.post("/api/queue/resume-all")
        self.assertEqual(resumed.status_code, 200)
        self.assertFalse(audit.load_config()["queue_paused"])

    def test_restore_workload_patch_preserves_checkpoint_size(self):
        restore = Path(self.temp.name) / "profile.restore"
        original = b"header\x00--workload-profile\n3\n--hwmon-temp-abort\n90\n"
        restore.write_bytes(original)
        self.assertTrue(audit.runner.patch_restore_workload(restore, 2))
        updated = restore.read_bytes()
        self.assertEqual(len(updated), len(original))
        self.assertIn(b"--workload-profile\n2\n", updated)

    def test_capture_import_and_queue(self):
        response = self.client.post("/api/captures", data={"files": (io.BytesIO(SAMPLE.encode()), "sample.22000")}, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 200)
        capture = response.get_json()["imported"][0]
        self.assertEqual(capture["networks"], 1)
        with audit.db() as connection:
            row = connection.execute("SELECT stored_path,hash_path FROM captures WHERE id=?", (capture["id"],)).fetchone()
            self.created_paths.extend(row)
            strategy = connection.execute("SELECT id FROM strategies WHERE mode='known'").fetchone()[0]
        queued = self.client.post("/api/queue", json={"capture_ids": [capture["id"]], "strategy_ids": [strategy]})
        self.assertEqual(queued.get_json()["created"], 1)

    def test_capture_reimport_keeps_only_new_networks(self):
        first = self.client.post(
            "/api/captures", data={"files": (io.BytesIO(SAMPLE.encode()), "first.22000")},
            content_type="multipart/form-data",
        )
        self.assertEqual(first.status_code, 200)
        variant = SAMPLE.strip().split("*")
        variant[3] = "001122334466"
        variant[5] = "4e65774e6574"  # NewNet
        mixed = SAMPLE + "*".join(variant) + "\n"
        second = self.client.post(
            "/api/captures", data={"files": (io.BytesIO(mixed.encode()), "mixed.22000")},
            content_type="multipart/form-data",
        )
        self.assertEqual(second.status_code, 200)
        imported = second.get_json()["imported"][0]
        self.assertEqual(imported["networks"], 1)
        self.assertEqual(imported["skipped_networks"], 1)
        with audit.db() as connection:
            rows = connection.execute("SELECT stored_path,hash_path FROM captures ORDER BY id").fetchall()
        self.created_paths.extend(path for row in rows for path in row)
        remaining = audit.parse_22000(Path(rows[-1]["hash_path"]))
        self.assertEqual([item["essid"] for item in remaining], ["NewNet"])

    def test_completed_method_memory_skips_same_network_and_source(self):
        hash_path = Path(self.temp.name) / "memory.22000"
        hash_path.write_text(SAMPLE, encoding="utf-8")
        source = Path(self.temp.name) / "memory.txt"
        source.write_text("password123\n", encoding="utf-8")
        other_source = Path(self.temp.name) / "memory-new.txt"
        other_source.write_text("different123\n", encoding="utf-8")
        with audit.db() as connection:
            capture_id = connection.execute(
                """INSERT INTO captures(filename,stored_path,hash_path,kind,networks,status,note,sha256,imported_at)
                   VALUES('memory.22000',?,?,'22000',1,'ready','','memory-capture',?)""",
                (str(hash_path), str(hash_path), audit.now()),
            ).lastrowid
            source_id = connection.execute(
                "INSERT INTO wordlists(filename,stored_path,kind,bytes,sha256,imported_at,position) VALUES(?,?,?,?,?,?,1)",
                (source.name, str(source), "wordlist", source.stat().st_size, "memory-source", audit.now()),
            ).lastrowid
            other_id = connection.execute(
                "INSERT INTO wordlists(filename,stored_path,kind,bytes,sha256,imported_at,position) VALUES(?,?,?,?,?,?,2)",
                (other_source.name, str(other_source), "wordlist", other_source.stat().st_size, "memory-source-new", audit.now()),
            ).lastrowid
            strategy_id = connection.execute(
                "INSERT INTO strategies(name,mode,config_json,position,enabled,builtin) VALUES('Memory dictionary','dictionary',?,99,1,0)",
                ('{"wordlist_id":%d}' % source_id,),
            ).lastrowid
            stage = dict(connection.execute("SELECT * FROM strategies WHERE id=?", (strategy_id,)).fetchone())
            descriptor = audit.strategy_attempt_descriptor(connection, stage)
            audit.insert_network_attempts(connection, {"id": 77, "mode": "dictionary", "attempt_key": descriptor[0], "attempt_label": descriptor[1]}, audit.parse_22000(hash_path))
            capture = dict(connection.execute("SELECT * FROM captures WHERE id=?", (capture_id,)).fetchone())
            self.assertEqual(audit.enqueue_matrix(connection, [capture], [stage], "capture_first", 3), 0)
            connection.execute("UPDATE strategies SET config_json=? WHERE id=?", ('{"wordlist_id":%d}' % other_id, strategy_id))
            changed_stage = dict(connection.execute("SELECT * FROM strategies WHERE id=?", (strategy_id,)).fetchone())
            self.assertEqual(audit.enqueue_matrix(connection, [capture], [changed_stage], "capture_first", 3), 1)

        state = self.client.get("/api/state").get_json()
        capture_state = next(item for item in state["captures"] if item["id"] == capture_id)
        self.assertEqual(capture_state["tested_method_count"], 1)
        self.assertIn("memory.txt", capture_state["attempted_methods"][0]["label"])

    def test_memory_backup_round_trip(self):
        audit.append_result("BackupNet", "AABBCCDDEEFF", "backup123", None, "Dictionary")
        with audit.db() as connection:
            connection.execute(
                """INSERT INTO network_attempts
                   (essid,bssid,method_key,mode,method_label,source_label,outcome,completed_at)
                   VALUES('BackupNet','AABBCCDDEEFF',?,'dictionary','Dictionary · backup.txt','backup.txt','recovered',?)""",
                ("a" * 64, audit.now()),
            )
        backup = self.client.get("/api/backup/export")
        self.assertEqual(backup.status_code, 200)
        with audit.db() as connection:
            connection.execute("DELETE FROM network_attempts")
            connection.execute("DELETE FROM results")
        restored = self.client.post(
            "/api/backup/restore", data={"file": (io.BytesIO(backup.data), "memory.json")},
            content_type="multipart/form-data",
        )
        self.assertEqual(restored.status_code, 200)
        self.assertEqual(restored.get_json()["results"], 1)
        self.assertEqual(restored.get_json()["attempts"], 1)

    def test_wordlist_import(self):
        response = self.client.post("/api/wordlists", data={"files": (io.BytesIO(b"examplepass\n"), "mine.txt")}, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 200)
        item_id = response.get_json()["imported"][0]["id"]
        with audit.db() as connection:
            path = connection.execute("SELECT stored_path FROM wordlists WHERE id=?", (item_id,)).fetchone()[0]
        self.created_paths.append(path)

    def test_cascade_deduplication_streams_in_source_order(self):
        root = Path(self.temp.name)
        first = root / "first.txt"
        rule = root / "mutate.rule"
        second = root / "second.dict"
        first.write_bytes(b"alpha\nbeta\nalpha\n")
        rule.write_text("$1\n", encoding="utf-8")
        second.write_bytes(b"beta\ngamma\nalpha\ndelta\ngamma\n")
        with audit.db() as connection:
            first_id = connection.execute(
                "INSERT INTO wordlists(filename,stored_path,kind,bytes,sha256,imported_at,position) VALUES(?,?,?,?,?,?,?)",
                (first.name, str(first), "wordlist", first.stat().st_size, "dedup-first", audit.now(), 1),
            ).lastrowid
            connection.execute(
                "INSERT INTO wordlists(filename,stored_path,kind,bytes,sha256,imported_at,position) VALUES(?,?,?,?,?,?,?)",
                (rule.name, str(rule), "rule", rule.stat().st_size, "dedup-rule", audit.now(), 1),
            )
            second_id = connection.execute(
                "INSERT INTO wordlists(filename,stored_path,kind,bytes,sha256,imported_at,position) VALUES(?,?,?,?,?,?,?)",
                (second.name, str(second), "wordlist", second.stat().st_size, "dedup-second", audit.now(), 2),
            ).lastrowid

        response = self.client.post("/api/wordlists/cascade-deduplicate", json={"paths": [str(first), str(rule), str(second)]})
        self.assertEqual(response.status_code, 200)
        result = response.get_json()
        self.assertEqual(result["processed_files"], 2)
        self.assertEqual(result["input_lines"], 8)
        self.assertEqual(result["written_lines"], 4)
        self.assertEqual(result["removed_lines"], 4)
        with audit.db() as connection:
            optimized = connection.execute(
                "SELECT id,filename,stored_path FROM wordlists WHERE id IN (?,?) ORDER BY position",
                (first_id, second_id),
            ).fetchall()
            saved_rule = connection.execute("SELECT stored_path FROM wordlists WHERE kind='rule'").fetchone()[0]
        self.assertEqual([row[1] for row in optimized], ["unique_first.txt", "unique_second.dict"])
        self.assertEqual(Path(optimized[0][2]).read_bytes(), b"alpha\nbeta\n")
        self.assertEqual(Path(optimized[1][2]).read_bytes(), b"gamma\ndelta\n")
        self.assertEqual(saved_rule, str(rule))
        self.assertEqual(first.read_bytes(), b"alpha\nbeta\nalpha\n")
        self.assertEqual(second.read_bytes(), b"beta\ngamma\nalpha\ndelta\ngamma\n")

    def test_wpa_filter_removes_only_candidates_shorter_than_eight_bytes(self):
        source = Path(self.temp.name) / "mixed.txt"
        original = b"short\n1234567\n12345678\npass word\nvery-long-password\n"
        source.write_bytes(original)
        with audit.db() as connection:
            item_id = connection.execute(
                "INSERT INTO wordlists(filename,stored_path,kind,bytes,sha256,imported_at,position) VALUES(?,?,?,?,?,?,?)",
                (source.name, str(source), "wordlist", source.stat().st_size, "filter-source", audit.now(), 1),
            ).lastrowid
        response = self.client.post(f"/api/wordlists/{item_id}/filter-short")
        self.assertEqual(response.status_code, 200)
        result = response.get_json()
        self.assertEqual(result["removed_lines"], 2)
        self.assertEqual(result["kept_lines"], 3)
        with audit.db() as connection:
            filtered = connection.execute("SELECT filename,stored_path,bytes FROM wordlists WHERE id=?", (item_id,)).fetchone()
        self.assertEqual(filtered[0], "wpa_mixed.txt")
        self.assertEqual(Path(filtered[1]).read_bytes(), b"12345678\npass word\nvery-long-password\n")
        self.assertEqual(filtered[2], Path(filtered[1]).stat().st_size)
        self.assertEqual(source.read_bytes(), original)

    def test_preset_expands_in_strategy_first_order(self):
        capture_ids = []
        for index in range(2):
            response = self.client.post(
                "/api/captures",
                data={"files": (io.BytesIO(SAMPLE.encode()), f"preset-{index}.22000")},
                content_type="multipart/form-data",
            )
            if index == 0:
                self.assertEqual(response.status_code, 200)
                capture_ids.append(response.get_json()["imported"][0]["id"])
            else:
                # Capture SHA deduplication is intentional, so clone the ready row for matrix-order testing.
                with audit.db() as connection:
                    original = connection.execute("SELECT * FROM captures WHERE id=?", (capture_ids[0],)).fetchone()
                    clone_parts = SAMPLE.strip().split("*")
                    clone_parts[3] = "001122334456"
                    clone_parts[5] = "546573744e657432"
                    clone_hash = Path(self.temp.name) / "preset-clone.22000"
                    clone_hash.write_text("*".join(clone_parts) + "\n", encoding="utf-8")
                    cursor = connection.execute(
                        """INSERT INTO captures(filename,stored_path,hash_path,kind,networks,status,note,sha256,imported_at)
                           VALUES(?,?,?,?,?,?,?,?,?)""",
                        ("preset-clone.22000", original["stored_path"], str(clone_hash), original["kind"],
                         original["networks"], "ready", "", "clone-digest", audit.now()),
                    )
                    capture_ids.append(cursor.lastrowid)

        for index in range(2):
            response = self.client.post(
                "/api/wordlists",
                data={"files": (io.BytesIO(f"password-{index}\n".encode()), f"ordered-{index}.txt")},
                content_type="multipart/form-data",
            )
            self.assertEqual(response.status_code, 200)
            with audit.db() as connection:
                self.created_paths.append(connection.execute(
                    "SELECT stored_path FROM wordlists WHERE id=?", (response.get_json()["imported"][0]["id"],)
                ).fetchone()[0])

        with audit.db() as connection:
            preset_id = connection.execute("SELECT id FROM presets WHERE name='Dictionary sweep'").fetchone()[0]
        queued = self.client.post(f"/api/presets/{preset_id}/queue", json={"capture_ids": capture_ids})
        self.assertEqual(queued.status_code, 200)
        self.assertEqual(queued.get_json()["created"], 6)
        with audit.db() as connection:
            rows = connection.execute(
                """SELECT j.capture_id,j.capture_ids_json,s.mode,s.name FROM jobs j JOIN strategies s ON s.id=j.strategy_id
                   ORDER BY j.id"""
            ).fetchall()
            paths = connection.execute("SELECT stored_path,hash_path FROM captures WHERE id=?", (capture_ids[0],)).fetchone()
            self.created_paths.extend(paths)
        self.assertEqual([row[0] for row in rows], capture_ids * 3)
        self.assertTrue(all(__import__("json").loads(row[1]) == [row[0]] for row in rows))
        self.assertEqual([row[2] for row in rows], ["known", "known", "dictionary", "dictionary", "dictionary", "dictionary"])

    def test_status_json_uses_only_hash_rate_component(self):
        with audit.db() as connection:
            connection.execute(
                """INSERT INTO captures(id,filename,stored_path,hash_path,kind,networks,status,note,sha256,imported_at)
                   VALUES(1,'x','x','x','22000',1,'ready','','status-digest',?)""", (audit.now(),)
            )
            strategy_id = connection.execute("SELECT id FROM strategies WHERE mode='known'").fetchone()[0]
            connection.execute(
                "INSERT INTO jobs(id,capture_id,strategy_id,status,session_name,created_at) VALUES(1,1,?,'running','status-test',?)",
                (strategy_id, audit.now()),
            )
        audit.runner.consume_status(1, '{"progress":[250,1000],"speed":[[123456.0,12.5],[200000.0,10.0]],"recovered_hashes":[1,2]}')
        with audit.db() as connection:
            row = connection.execute("SELECT progress,speed_hps,recovered FROM jobs WHERE id=1").fetchone()
        self.assertEqual(row[0], 25.0)
        self.assertEqual(row[1], 323456.0)
        self.assertEqual(row[2], 1)

        audit.runner.consume_status(1, 'prompt => { "session":"hashcat","progress":[500,1000],"devices":[{"speed":333479}],"recovered_hashes":[1,2]}')
        with audit.db() as connection:
            row = connection.execute("SELECT progress,speed_hps FROM jobs WHERE id=1").fetchone()
        self.assertEqual(row[0], 50.0)
        self.assertEqual(row[1], 333479.0)


if __name__ == "__main__":
    unittest.main()
