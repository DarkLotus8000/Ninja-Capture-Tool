# Run from the project root with: py -B -m unittest discover -s tests
from support import *

class UpdateTests(NctTestBase):
    def test_update_progress_matches_capture_progress_layout_and_color(self) -> None:
        progress = update._UpdateProgress(
            "[Update]",
            60 * 1024 * 1024,
            "NinjaCaptureTool-v1.1.0-Windows-x64.zip",
        )
        progress.completed = 30 * 1024 * 1024
        progress.speed_samples.clear()
        progress.speed_samples.append((100.0, 24 * 1024 * 1024))
        stdout = io.StringIO()
        with (
            mock.patch.object(common, "console_supports_color", return_value=True),
            mock.patch.object(update.shutil, "get_terminal_size", return_value=os.terminal_size((160, 24))),
            contextlib.redirect_stdout(stdout),
        ):
            progress._render_interactive(101.0)
        self.assertEqual(
            stdout.getvalue(),
            "\r[Update] \x1b[36m30.0 MiB / 60.0 MiB (50.0%)\x1b[0m | 6.0 MiB/s | "
            "NinjaCaptureTool-v1.1.0-Windows-x64.zip",
        )

    def test_check_update_reports_local_newer_version(self) -> None:
        output = io.StringIO()
        release = {"version": "0.9.0", "url": "https://github.com/example/release"}
        with (
            mock.patch.object(update, "latest_release", return_value=release),
            mock.patch.object(update, "_record_update_check_result") as record,
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(update.check_update_only(), 0)
        self.assertIn(f"Local Ninja Capture Tool v{common.display_version()} is newer", output.getvalue())
        record.assert_called_once_with("success")

    def test_update_check_cooldown_uses_success_and_failure_intervals(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "update_state.json"
            with mock.patch.object(update, "UPDATE_STATE_FILE", path):
                path.write_text('{"last_successful_check": 1000}', encoding="utf-8")
                self.assertFalse(update.automatic_update_check_due(now=1000 + 60 * 60))
                self.assertTrue(update.automatic_update_check_due(now=1000 + 24 * 60 * 60))
                path.write_text('{"last_failed_check": 2000}', encoding="utf-8")
                self.assertFalse(update.automatic_update_check_due(now=2000 + 5 * 60))
                self.assertTrue(update.automatic_update_check_due(now=2000 + 15 * 60))

    def test_corrupted_update_state_is_replaced_after_next_recorded_check(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "update_state.json"
            path.write_text("{not-json", encoding="utf-8")
            with (
                mock.patch.object(update, "UPDATE_STATE_FILE", path),
                mock.patch.object(update.sys, "frozen", True, create=True),
            ):
                self.assertTrue(update.automatic_update_check_due(now=123))
                update._record_update_check_result("success", now=123)
            self.assertEqual(common.read_json_object(path), {"last_successful_check": 123})

    def test_explicit_auto_update_bypasses_check_cooldown(self) -> None:
        args = SimpleNamespace(no_auto_update=False, auto_update=True)
        with (
            mock.patch.object(update.sys, "frozen", True, create=True),
            mock.patch.object(update, "automatic_update_check_due") as cooldown,
            mock.patch.object(update, "check_for_update", return_value=None) as check,
            mock.patch.object(update, "_record_update_check_result") as record,
        ):
            self.assertIsNone(update.handle_automatic_update(args, [], True))
        cooldown.assert_not_called()
        check.assert_called_once_with()
        record.assert_called_once_with("success")

    def test_failed_automatic_update_check_records_short_retry_cooldown(self) -> None:
        args = SimpleNamespace(no_auto_update=False, auto_update=False)
        with (
            mock.patch.object(update.sys, "frozen", True, create=True),
            mock.patch.object(update, "automatic_update_check_due", return_value=True),
            mock.patch.object(update, "check_for_update", side_effect=OSError("offline")),
            mock.patch.object(update, "_record_update_check_result") as record,
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertIsNone(update.handle_automatic_update(args, [], True))
        record.assert_called_once_with("failure")

    def test_source_update_checks_do_not_persist_cooldown_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "update_state.json"
            with (
                mock.patch.object(update, "UPDATE_STATE_FILE", state_path),
                mock.patch.object(update.sys, "frozen", False, create=True),
            ):
                update._record_update_check_result("success", now=123)
            self.assertFalse(state_path.exists())

    def test_frozen_update_check_persists_portable_cooldown_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "update_state.json"
            with (
                mock.patch.object(update, "UPDATE_STATE_FILE", state_path),
                mock.patch.object(update.sys, "frozen", True, create=True),
            ):
                update._record_update_check_result("success", now=123)
            self.assertEqual(common.read_json_object(state_path), {"last_successful_check": 123})

    def test_explicit_update_check_must_be_standalone(self) -> None:
        with mock.patch.object(update, "check_update_only", return_value=0) as check:
            self.assertEqual(update.handle_early_update_request(["-U"]), 0)
        check.assert_called_once_with()
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                update.handle_early_update_request(["-U", "-m", "local"])

    def test_update_download_rejects_excess_bytes_before_writing_them(self) -> None:
        class Response(io.BytesIO):
            def __enter__(self):
                return self
            def __exit__(self, *args):
                self.close()

        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "release.zip"
            with mock.patch.object(update, "_request", return_value=Response(b"123456")):
                with self.assertRaisesRegex(RuntimeError, "exceeds the expected size"):
                    update._download_file("https://example.test/release.zip", destination, expected_size=5)
            self.assertFalse(destination.exists())
            self.assertFalse(destination.with_name(destination.name + ".part").exists())

    def test_update_metadata_response_has_size_limit(self) -> None:
        class Response(io.BytesIO):
            def __enter__(self):
                return self
            def __exit__(self, *args):
                self.close()

        payload = b"{" + b" " * update.MAX_GITHUB_JSON_BYTES + b"}"
        with mock.patch.object(update, "_request", return_value=Response(payload)):
            with self.assertRaisesRegex(RuntimeError, "unexpectedly large"):
                update._request_json("https://example.test/latest")

    def test_available_update_validates_self_copy_before_download(self) -> None:
        args = SimpleNamespace(no_auto_update=False, auto_update=False)
        release = {"version": "1.2.0", "assets": [], "url": "https://github.com/example/release"}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            temp_root = root / "temp"
            with (
                mock.patch.object(update.sys, "frozen", True, create=True),
                mock.patch.object(update, "TOOL_DIR", root),
                mock.patch.object(update, "TEMP_ROOT", temp_root),
                mock.patch.object(update, "automatic_update_check_due", return_value=True),
                mock.patch.object(update, "check_for_update", return_value=release),
                mock.patch.object(update, "_copy_application_for_update", side_effect=RuntimeError("bad executable")) as copy_updater,
                mock.patch.object(update, "download_release") as download,
                mock.patch.object(update, "_record_update_check_result") as record,
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertIsNone(update.handle_automatic_update(args, [], True))
            copy_updater.assert_called_once()
            download.assert_not_called()
            record.assert_called_once_with("update_available")

    def test_self_copy_stays_in_update_work_and_is_validated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "NinjaCaptureTool.exe"
            runtime = root / common.FROZEN_RUNTIME_DIR_NAME
            work = root / "temp" / "update_test"
            source.write_bytes(b"application")
            runtime.mkdir()
            (runtime / "python314.dll").write_bytes(b"runtime")
            work.mkdir(parents=True)
            with (
                mock.patch.object(update.sys, "executable", str(source)),
                mock.patch.object(update, "_validate_temporary_updater") as validate_copy,
            ):
                copied = update._copy_application_for_update(work)
            self.assertEqual(copied, work / "NinjaCaptureToolUpdater.exe")
            self.assertEqual(copied.read_bytes(), b"application")
            self.assertEqual(
                (work / common.FROZEN_RUNTIME_DIR_NAME / "python314.dll").read_bytes(),
                b"runtime",
            )
            validate_copy.assert_called_once_with(copied)

    def test_update_handoff_uses_self_copy_inside_update_work(self) -> None:
        temporary = Path("C:/Ninja Capture Tool/temp/update_test/NinjaCaptureToolUpdater.exe")
        stage = Path("C:/Ninja Capture Tool/temp/update_test/stage")
        with (
            mock.patch.object(update, "_validate_temporary_updater") as validate,
            mock.patch.object(update.sys, "executable", r"C:\Ninja Capture Tool\NinjaCaptureTool.exe"),
            mock.patch.object(update.os, "getpid", return_value=1234),
            mock.patch.object(update.Path, "cwd", return_value=Path("C:/Ninja Capture Tool")),
            mock.patch.object(update.subprocess, "Popen") as popen,
        ):
            update.launch_updater(temporary, stage, ["-o", "output/U43.5.4"], "1.1.0")
        validate.assert_called_once_with(temporary)
        command = popen.call_args.args[0]
        self.assertEqual(command[0], str(temporary))
        self.assertEqual(command[1], "--update-installer")
        self.assertFalse(any(Path(part).name.casefold() == "updater.exe" for part in command))
        self.assertEqual(command[-2:], ["-o", "output/U43.5.4"])
        self.assertNotIn("PYINSTALLER_RESET_ENVIRONMENT", popen.call_args.kwargs["env"])

    def test_stale_update_cleanup_preserves_active_self_updater(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp_root = Path(tmp) / "temp"
            work = temp_root / "update_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            work.mkdir(parents=True)
            (work / update.UPDATE_SESSION_FILE).write_text(
                '{"pid": 1234, "process_identity": "1234:5678"}', encoding="utf-8"
            )
            old = time.time() - (7 * 24 * 60 * 60) - 60
            os.utime(work, (old, old))
            with (
                mock.patch.object(update, "TOOL_DIR", Path(tmp)),
                mock.patch.object(update, "TEMP_ROOT", temp_root),
                mock.patch.object(update.sys, "platform", "win32"),
                mock.patch.object(update, "process_matches_identity", return_value=True) as active,
            ):
                update.cleanup_stale_update_work()
            self.assertTrue(work.is_dir())
            active.assert_called_once_with(1234, "1234:5678")

    def test_stale_update_cleanup_removes_inactive_work(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp_root = Path(tmp) / "temp"
            work = temp_root / "update_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            work.mkdir(parents=True)
            (work / update.UPDATE_SESSION_FILE).write_text(
                '{"pid": 1234, "process_identity": "1234:5678"}', encoding="utf-8"
            )
            old = time.time() - (7 * 24 * 60 * 60) - 60
            os.utime(work, (old, old))
            with (
                mock.patch.object(update, "TOOL_DIR", Path(tmp)),
                mock.patch.object(update, "TEMP_ROOT", temp_root),
                mock.patch.object(update.sys, "platform", "win32"),
                mock.patch.object(update, "process_matches_identity", return_value=False),
            ):
                update.cleanup_stale_update_work()
            self.assertFalse(work.exists())
            self.assertFalse(temp_root.exists())

    def test_stale_update_cleanup_removes_malformed_session_without_backup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            temp_root = root / "temp"
            work = temp_root / "update_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            work.mkdir(parents=True)
            (work / update.UPDATE_SESSION_FILE).write_text("{not-json", encoding="utf-8")
            old = time.time() - (7 * 24 * 60 * 60) - 60
            os.utime(work, (old, old))
            with (
                mock.patch.object(update, "TOOL_DIR", root),
                mock.patch.object(update, "TEMP_ROOT", temp_root),
                mock.patch.object(update.sys, "platform", "win32"),
            ):
                update.cleanup_stale_update_work()
            self.assertFalse(work.exists())
            self.assertFalse(temp_root.exists())

    def test_stale_update_cleanup_removes_invalid_session_identity_without_backup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            temp_root = root / "temp"
            work = temp_root / "update_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            work.mkdir(parents=True)
            (work / update.UPDATE_SESSION_FILE).write_text(
                json.dumps({"pid": 1234, "process_identity": None, "transaction_state": "active"}),
                encoding="utf-8",
            )
            old = time.time() - (7 * 24 * 60 * 60) - 60
            os.utime(work, (old, old))
            with (
                mock.patch.object(update, "TOOL_DIR", root),
                mock.patch.object(update, "TEMP_ROOT", temp_root),
                mock.patch.object(update.sys, "platform", "win32"),
                mock.patch.object(update, "process_matches_identity") as inspect_process,
            ):
                update.cleanup_stale_update_work()
            self.assertFalse(work.exists())
            inspect_process.assert_not_called()

    def test_malformed_session_never_makes_recovery_backup_disposable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            temp_root = root / "temp"
            work = temp_root / "update_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            backup = work / "backup_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            backup.mkdir(parents=True)
            (backup / "NinjaCaptureTool.exe").write_bytes(b"old")
            (work / update.UPDATE_SESSION_FILE).write_text("{not-json", encoding="utf-8")
            old = time.time() - (7 * 24 * 60 * 60) - 60
            os.utime(work, (old, old))
            with (
                mock.patch.object(update, "TOOL_DIR", root),
                mock.patch.object(update, "TEMP_ROOT", temp_root),
                mock.patch.object(update.sys, "platform", "win32"),
            ):
                update.cleanup_stale_update_work()
                self.assertEqual(update.stale_update_recovery_backups(), [work])
            self.assertTrue(work.is_dir())
            self.assertTrue(backup.is_dir())

    def test_stale_update_cleanup_preserves_valid_session_when_process_inspection_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            temp_root = root / "temp"
            work = temp_root / "update_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            work.mkdir(parents=True)
            (work / update.UPDATE_SESSION_FILE).write_text(
                json.dumps({"pid": 1234, "process_identity": "1234:5678", "transaction_state": "active"}),
                encoding="utf-8",
            )
            old = time.time() - (7 * 24 * 60 * 60) - 60
            os.utime(work, (old, old))
            with (
                mock.patch.object(update, "TOOL_DIR", root),
                mock.patch.object(update, "TEMP_ROOT", temp_root),
                mock.patch.object(update.sys, "platform", "win32"),
                mock.patch.object(update, "process_matches_identity", side_effect=OSError("inspection failed")),
            ):
                update.cleanup_stale_update_work()
            self.assertTrue(work.is_dir())

    def test_stale_update_cleanup_ignores_non_owned_update_prefix_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            temp_root = root / "temp"
            work = temp_root / "update_notes"
            work.mkdir(parents=True)
            old = time.time() - (7 * 24 * 60 * 60) - 60
            os.utime(work, (old, old))
            with (
                mock.patch.object(update, "TOOL_DIR", root),
                mock.patch.object(update, "TEMP_ROOT", temp_root),
            ):
                update.cleanup_stale_update_work()
            self.assertTrue(work.is_dir())

    def test_backup_prefix_without_real_backup_id_is_not_recovery_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            temp_root = root / "temp"
            work = temp_root / "update_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            (work / "backup_notes").mkdir(parents=True)
            old = time.time() - (7 * 24 * 60 * 60) - 60
            os.utime(work, (old, old))
            with (
                mock.patch.object(update, "TOOL_DIR", root),
                mock.patch.object(update, "TEMP_ROOT", temp_root),
            ):
                self.assertEqual(update.stale_update_recovery_backups(), [])
                update.cleanup_stale_update_work()
            self.assertFalse(work.exists())

    def test_stale_update_cleanup_never_traverses_redirected_temp_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install = root / "install"
            external = root / "external"
            install.mkdir()
            external.mkdir()
            work = external / "update_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            work.mkdir()
            marker = work / "keep.txt"
            marker.write_text("keep", encoding="utf-8")
            old = time.time() - (7 * 24 * 60 * 60) - 60
            os.utime(work, (old, old))
            temp_root = install / "temp"
            try:
                temp_root.symlink_to(external, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"Directory symlink creation is unavailable: {exc}")
            with (
                mock.patch.object(update, "TOOL_DIR", install),
                mock.patch.object(update, "TEMP_ROOT", temp_root),
            ):
                update.cleanup_stale_update_work()
                self.assertEqual(update.stale_update_recovery_backups(), [])
            self.assertEqual(marker.read_text(encoding="utf-8"), "keep")

    def test_automatic_update_interrupt_removes_empty_temp_root(self) -> None:
        args = SimpleNamespace(no_auto_update=False, auto_update=True)
        release = {"version": "1.1.0", "assets": [], "url": "https://github.com/example/release"}
        with tempfile.TemporaryDirectory() as tmp:
            temp_root = Path(tmp) / "temp"
            with (
                mock.patch.object(update.sys, "frozen", True, create=True),
                mock.patch.object(update, "TOOL_DIR", Path(tmp)),
                mock.patch.object(update, "TEMP_ROOT", temp_root),
                mock.patch.object(update, "automatic_update_check_due", return_value=True),
                mock.patch.object(update, "check_for_update", return_value=release),
                mock.patch.object(update, "_copy_application_for_update", return_value=Path("NinjaCaptureToolUpdater.exe")),
                mock.patch.object(update, "_record_update_check_result"),
                mock.patch.object(update, "download_release", side_effect=KeyboardInterrupt),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(update.handle_automatic_update(args, [], True), 130)
            self.assertFalse(temp_root.exists())

    def test_updater_session_records_pid_and_process_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            with (
                mock.patch.object(update.os, "getpid", return_value=1234),
                mock.patch.object(update, "process_identity", return_value="1234:5678") as identity,
            ):
                update.write_update_session(work)
            state = json.loads((work / update.UPDATE_SESSION_FILE).read_text(encoding="utf-8"))
            self.assertEqual(
                state,
                {
                    "pid": 1234,
                    "process_identity": "1234:5678",
                    "transaction_state": "active",
                },
            )
            identity.assert_called_once_with(1234)

    def test_updater_session_commit_preserves_identity_and_marks_transaction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            session = work / update.UPDATE_SESSION_FILE
            session.write_text(
                json.dumps(
                    {
                        "pid": 1234,
                        "process_identity": "1234:5678",
                        "transaction_state": "active",
                    }
                ),
                encoding="utf-8",
            )
            update.mark_update_session_committed(work)
            self.assertEqual(
                json.loads(session.read_text(encoding="utf-8")),
                {
                    "pid": 1234,
                    "process_identity": "1234:5678",
                    "transaction_state": "committed",
                },
            )

    def test_updater_session_rollback_preserves_identity_and_marks_transaction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            session = work / update.UPDATE_SESSION_FILE
            session.write_text(
                json.dumps(
                    {
                        "pid": 1234,
                        "process_identity": "1234:5678",
                        "transaction_state": "active",
                    }
                ),
                encoding="utf-8",
            )
            update.mark_update_session_rolled_back(work)
            self.assertEqual(
                json.loads(session.read_text(encoding="utf-8")),
                {
                    "pid": 1234,
                    "process_identity": "1234:5678",
                    "transaction_state": "rolled_back",
                },
            )
            self.assertTrue(update._update_session_backup_is_disposable(work))

    def test_committed_update_session_state_is_not_trusted_through_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work = root / "work"
            work.mkdir()
            external = root / "external.json"
            external.write_text(
                json.dumps(
                    {
                        "pid": 1234,
                        "process_identity": "1234:5678",
                        "transaction_state": "committed",
                    }
                ),
                encoding="utf-8",
            )
            try:
                (work / update.UPDATE_SESSION_FILE).symlink_to(external)
            except OSError as exc:
                self.skipTest(f"File symlink creation is unavailable: {exc}")
            self.assertFalse(update._update_session_backup_is_disposable(work))
            with self.assertRaisesRegex(RuntimeError, "not a real regular file"):
                update.mark_update_session_committed(work)

    def test_relaunched_update_cleanup_removes_own_work_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp_root = Path(tmp) / "temp"
            work = temp_root / "update_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            work.mkdir(parents=True)
            (work / "NinjaCaptureToolUpdater.exe").write_bytes(b"old updater copy")
            with (
                mock.patch.object(update, "TOOL_DIR", Path(tmp)),
                mock.patch.object(update, "TEMP_ROOT", temp_root),
                mock.patch.dict(os.environ, {"NCT_UPDATE_WORK_CLEANUP": str(work)}, clear=False),
            ):
                update.cleanup_relaunched_update_work()
            self.assertFalse(work.exists())
            self.assertFalse(temp_root.exists())

    def test_relaunched_update_cleanup_removes_committed_backup_debris(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp_root = Path(tmp) / "temp"
            work = temp_root / "update_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            backup = work / "backup_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            backup.mkdir(parents=True)
            (backup / "NinjaCaptureTool.exe").write_bytes(b"old")
            (work / update.UPDATE_SESSION_FILE).write_text(
                json.dumps(
                    {
                        "pid": 1234,
                        "process_identity": "1234:5678",
                        "transaction_state": "committed",
                    }
                ),
                encoding="utf-8",
            )
            with (
                mock.patch.object(update, "TOOL_DIR", Path(tmp)),
                mock.patch.object(update, "TEMP_ROOT", temp_root),
                mock.patch.dict(os.environ, {"NCT_UPDATE_WORK_CLEANUP": str(work)}, clear=False),
            ):
                update.cleanup_relaunched_update_work()
            self.assertFalse(work.exists())
            self.assertFalse(temp_root.exists())

    def test_relaunched_update_cleanup_ignores_non_owned_update_prefix_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            temp_root = root / "temp"
            work = temp_root / "update_notes"
            work.mkdir(parents=True)
            marker = work / "keep.txt"
            marker.write_text("keep", encoding="utf-8")
            with (
                mock.patch.object(update, "TOOL_DIR", root),
                mock.patch.object(update, "TEMP_ROOT", temp_root),
                mock.patch.dict(os.environ, {"NCT_UPDATE_WORK_CLEANUP": str(work)}, clear=False),
            ):
                update.cleanup_relaunched_update_work()
            self.assertEqual(marker.read_text(encoding="utf-8"), "keep")

    def test_updater_relaunch_requests_update_work_cleanup(self) -> None:
        captured: dict[str, object] = {}

        def fake_popen(command, cwd=None, env=None):
            captured["command"] = command
            captured["cwd"] = cwd
            captured["env"] = env
            return object()

        work = Path("C:/Ninja Capture Tool/temp/update_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        with mock.patch.object(update.subprocess, "Popen", side_effect=fake_popen):
            update.relaunch(Path("NinjaCaptureTool.exe"), ["-o", "capture"], Path("C:/Ninja Capture Tool"), work)
        self.assertNotIn("PYINSTALLER_RESET_ENVIRONMENT", captured["env"])
        self.assertEqual(captured["env"]["NCT_SKIP_UPDATE_CHECK_ONCE"], "1")
        self.assertEqual(captured["env"]["NCT_UPDATE_WORK_CLEANUP"], str(work))
        self.assertEqual(captured["command"], ["NinjaCaptureTool.exe", "-o", "capture"])

    def test_main_dispatches_internal_update_installer_mode(self) -> None:
        with mock.patch.object(nct, "run_update_installer", return_value=7) as installer:
            self.assertEqual(nct.main(["--update-installer", "--target-version", "1.1.0"]), 7)
        installer.assert_called_once_with(["--target-version", "1.1.0"])

    def test_updater_replaces_onedir_runtime_as_one_transaction_and_rolls_back(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install = root / "install"
            stage = root / "work" / "stage"
            old_runtime = install / common.FROZEN_RUNTIME_DIR_NAME
            new_runtime = stage / common.FROZEN_RUNTIME_DIR_NAME
            old_runtime.mkdir(parents=True)
            new_runtime.mkdir(parents=True)
            (old_runtime / "obsolete.dll").write_bytes(b"old-runtime")
            (new_runtime / "python314.dll").write_bytes(b"new-runtime")
            (install / "NinjaCaptureTool.exe").write_bytes(b"old-main")
            (stage / "NinjaCaptureTool.exe").write_bytes(b"new-main")
            self._write_stage_release_manifest(stage)

            backup, changes = update.install_staged_release(stage, install, common.VERSION)

            self.assertFalse((install / common.FROZEN_RUNTIME_DIR_NAME / "obsolete.dll").exists())
            self.assertEqual(
                (install / common.FROZEN_RUNTIME_DIR_NAME / "python314.dll").read_bytes(),
                b"new-runtime",
            )
            self.assertEqual((install / "NinjaCaptureTool.exe").read_bytes(), b"new-main")
            self.assertEqual(
                (backup / common.FROZEN_RUNTIME_DIR_NAME / "obsolete.dll").read_bytes(),
                b"old-runtime",
            )

            update.rollback_staged_release(changes, backup)
            self.assertEqual(
                (install / common.FROZEN_RUNTIME_DIR_NAME / "obsolete.dll").read_bytes(),
                b"old-runtime",
            )
            self.assertFalse((install / common.FROZEN_RUNTIME_DIR_NAME / "python314.dll").exists())
            self.assertEqual((install / "NinjaCaptureTool.exe").read_bytes(), b"old-main")

    def test_updater_preserves_work_when_install_rollback_is_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install = root / "install"
            stage = install / "temp" / ("update_" + "a" * 32) / "stage"
            backup = stage.parent / "backup_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            install.mkdir(parents=True)
            stage.mkdir(parents=True)
            backup.mkdir()
            executable = install / "NinjaCaptureTool.exe"
            with (
                mock.patch.object(update.sys, "platform", "win32"),
                mock.patch.object(update, "write_update_session"),
                mock.patch.object(update, "wait_for_process_exit"),
                mock.patch.object(update, "updater_install_lock", return_value=contextlib.nullcontext()),
                mock.patch.object(update, "capture_install_lock", return_value=contextlib.nullcontext()),
                mock.patch.object(update, "installed_executable_satisfies_target", return_value=None),
                mock.patch.object(update, "install_staged_release", side_effect=RuntimeError("rollback incomplete")),
                mock.patch.object(update, "relaunch") as relaunch,
                contextlib.redirect_stderr(io.StringIO()),
            ):
                result = update.run_update_installer([
                    "--install-dir", str(install),
                    "--stage-dir", str(stage),
                    "--parent-pid", "123",
                    "--target-version", "1.1.0",
                    "--relaunch-executable", str(executable),
                    "--relaunch-cwd", str(root),
                ])
            self.assertEqual(result, 1)
            self.assertTrue(backup.is_dir())
            relaunch.assert_not_called()

    def test_updater_rollback_restores_replaced_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install = root / "install"
            stage = root / "work" / "stage"
            install.mkdir(parents=True)
            stage.mkdir(parents=True)
            (install / "NinjaCaptureTool.exe").write_bytes(b"old")
            (stage / "NinjaCaptureTool.exe").write_bytes(b"new")
            self._write_stage_release_manifest(stage)
            backup, changes = update.install_staged_release(stage, install, common.VERSION)
            self.assertEqual((install / "NinjaCaptureTool.exe").read_bytes(), b"new")
            update.rollback_staged_release(changes, backup)
            self.assertEqual((install / "NinjaCaptureTool.exe").read_bytes(), b"old")

    def test_successful_rollback_marks_terminal_before_best_effort_backup_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work = root / "update_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            backup = work / "backup_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            install = root / "install"
            work.mkdir()
            backup.mkdir()
            install.mkdir()
            session = work / update.UPDATE_SESSION_FILE
            session.write_text(
                json.dumps(
                    {
                        "pid": 1234,
                        "process_identity": "1234:5678",
                        "transaction_state": "active",
                    }
                ),
                encoding="utf-8",
            )
            destination = install / "NinjaCaptureTool.exe"
            saved = backup / "NinjaCaptureTool.exe"
            destination.write_bytes(b"new")
            saved.write_bytes(b"old")

            original_rmtree = update.shutil.rmtree
            def keep_backup(path, *args, **kwargs):
                if Path(path) == backup:
                    return None
                return original_rmtree(path, *args, **kwargs)

            with mock.patch.object(update.shutil, "rmtree", side_effect=keep_backup):
                update.rollback_staged_release([(destination, saved)], backup, work)

            self.assertEqual(destination.read_bytes(), b"old")
            self.assertTrue(backup.is_dir())
            self.assertEqual(json.loads(session.read_text(encoding="utf-8"))["transaction_state"], "rolled_back")
            self.assertTrue(update._update_session_backup_is_disposable(work))

    def test_rollback_state_write_failure_preserves_backup_after_restoring_installation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work = root / "update_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            backup = work / "backup_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            install = root / "install"
            work.mkdir()
            backup.mkdir()
            install.mkdir()
            destination = install / "NinjaCaptureTool.exe"
            saved = backup / "NinjaCaptureTool.exe"
            destination.write_bytes(b"new")
            saved.write_bytes(b"old")

            with (
                mock.patch.object(update, "mark_update_session_rolled_back", side_effect=OSError("state write failed")),
                self.assertRaisesRegex(RuntimeError, "could not record its terminal state"),
            ):
                update.rollback_staged_release([(destination, saved)], backup, work)

            self.assertEqual(destination.read_bytes(), b"old")
            self.assertTrue(backup.is_dir())

    def test_updater_relaunches_after_rollback_even_if_terminal_backup_cleanup_is_delayed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install = root / "install"
            temp_root = install / "temp"
            work = temp_root / "update_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            stage = work / "stage"
            backup = work / "backup_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            install.mkdir(parents=True)
            stage.mkdir(parents=True)
            backup.mkdir()
            executable = install / "NinjaCaptureTool.exe"
            executable.write_bytes(b"new")
            saved = backup / "NinjaCaptureTool.exe"
            saved.write_bytes(b"old")
            changes = [(executable, saved)]

            def write_session(current_work: Path) -> None:
                (current_work / update.UPDATE_SESSION_FILE).write_text(
                    json.dumps(
                        {
                            "pid": 1234,
                            "process_identity": "1234:5678",
                            "transaction_state": "active",
                        }
                    ),
                    encoding="utf-8",
                )

            original_rmtree = update.shutil.rmtree
            def keep_backup(path, *args, **kwargs):
                if Path(path) == backup:
                    return None
                return original_rmtree(path, *args, **kwargs)

            with (
                mock.patch.object(update.sys, "platform", "win32"),
                mock.patch.object(update, "write_update_session", side_effect=write_session),
                mock.patch.object(update, "wait_for_process_exit"),
                mock.patch.object(update, "updater_install_lock", return_value=contextlib.nullcontext()),
                mock.patch.object(update, "capture_install_lock", return_value=contextlib.nullcontext()),
                mock.patch.object(update, "installed_executable_satisfies_target", return_value=None),
                mock.patch.object(update, "install_staged_release", return_value=(backup, changes)),
                mock.patch.object(update, "validate_installed_executable", side_effect=RuntimeError("validation failed")),
                mock.patch.object(update, "relaunch") as relaunch,
                mock.patch.object(update.shutil, "rmtree", side_effect=keep_backup),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                result = update.run_update_installer([
                    "--install-dir", str(install),
                    "--stage-dir", str(stage),
                    "--parent-pid", "123",
                    "--target-version", "1.1.0",
                    "--relaunch-executable", str(executable),
                    "--relaunch-cwd", str(root),
                ])

            self.assertEqual(result, 1)
            self.assertEqual(executable.read_bytes(), b"old")
            self.assertTrue(backup.is_dir())
            self.assertEqual(
                json.loads((work / update.UPDATE_SESSION_FILE).read_text(encoding="utf-8"))["transaction_state"],
                "rolled_back",
            )
            self.assertTrue(update._update_session_backup_is_disposable(work))
            relaunch.assert_called_once_with(executable.resolve(), [], root.resolve(), work)

            with (
                mock.patch.object(update, "TOOL_DIR", install),
                mock.patch.object(update, "TEMP_ROOT", temp_root),
                mock.patch.dict(os.environ, {"NCT_UPDATE_WORK_CLEANUP": str(work)}, clear=False),
            ):
                update.cleanup_relaunched_update_work()
            self.assertFalse(work.exists())

    def test_updater_rejects_staged_version_mismatch_before_backup_or_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install = root / "install"
            stage = root / "work" / "stage"
            install.mkdir(parents=True)
            stage.mkdir(parents=True)
            installed = install / "NinjaCaptureTool.exe"
            installed.write_bytes(b"old")
            (stage / "NinjaCaptureTool.exe").write_bytes(b"unexpected-release")
            self._write_stage_release_manifest(stage, "9.9.9")

            with self.assertRaisesRegex(RuntimeError, "expected target version"):
                update.install_staged_release(stage, install, "1.1.0")

            self.assertEqual(installed.read_bytes(), b"old")
            self.assertEqual((stage / "NinjaCaptureTool.exe").read_bytes(), b"unexpected-release")
            self.assertFalse(any(update._UPDATE_BACKUP_NAME_RE.fullmatch(path.name) for path in stage.parent.iterdir()))

    def test_release_manifest_rejects_preserved_paths_case_insensitively(self) -> None:
        for managed_path in (
            "CONFIG.JSON",
            "DATA/RELEASE_MANIFEST.JSON",
        ):
            with self.subTest(managed_path=managed_path), tempfile.TemporaryDirectory() as tmp:
                manifest = Path(tmp) / "release_manifest.json"
                manifest.write_text(
                    json.dumps(
                        {
                            "format_version": common.RELEASE_MANIFEST_VERSION,
                            "application_version": common.VERSION,
                            "files": {managed_path: "0" * 64},
                        }
                    ),
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(RuntimeError, "invalid managed path"):
                    update._parse_release_manifest(manifest)

    def test_updater_rejects_invalid_target_version_before_workspace_validation(self) -> None:
        with (
            mock.patch.object(update.sys, "platform", "win32"),
            mock.patch.object(update, "_validate_update_workspace") as validate_workspace,
            contextlib.redirect_stderr(io.StringIO()),
        ):
            result = update.run_update_installer([
                "--install-dir", "C:/NCT",
                "--stage-dir", "C:/NCT/temp/update_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/stage",
                "--parent-pid", "123",
                "--target-version", "not-a-version",
                "--relaunch-executable", "C:/NCT/NinjaCaptureTool.exe",
                "--relaunch-cwd", "C:/NCT",
            ])

        self.assertEqual(result, 1)
        validate_workspace.assert_not_called()

    def test_post_install_validation_accepts_display_equivalent_version(self) -> None:
        with mock.patch.object(update, "_read_installed_version", return_value="1.0"):
            update.validate_installed_executable(Path("NinjaCaptureTool.exe"), "1.0.0", Path("."))

    def test_post_install_validation_rejects_different_version(self) -> None:
        with mock.patch.object(update, "_read_installed_version", return_value="1.0.1"):
            with self.assertRaisesRegex(RuntimeError, "expected v1.0, got v1.0.1"):
                update.validate_installed_executable(Path("NinjaCaptureTool.exe"), "1.0.0", Path("."))

    def test_queued_updater_accepts_equal_or_newer_installed_version(self) -> None:
        with mock.patch.object(update, "_read_installed_version", return_value="1.3.0"):
            self.assertEqual(
                update.installed_executable_satisfies_target(Path("NinjaCaptureTool.exe"), "1.2.0", Path(".")),
                "1.3.0",
            )
        with mock.patch.object(update, "_read_installed_version", return_value="1.1.0"):
            self.assertIsNone(
                update.installed_executable_satisfies_target(Path("NinjaCaptureTool.exe"), "1.2.0", Path("."))
            )

    def test_temporary_updater_version_validation_uses_bounded_timeout(self) -> None:
        result = SimpleNamespace(returncode=0, stdout=f"Ninja Capture Tool v{common.display_version()}\n", stderr="")
        with mock.patch.object(update.subprocess, "run", return_value=result) as run:
            update._validate_temporary_updater(Path("NinjaCaptureToolUpdater.exe"))
        self.assertEqual(run.call_args.kwargs["timeout"], 150)
        self.assertNotIn("PYINSTALLER_RESET_ENVIRONMENT", run.call_args.kwargs["env"])

    def test_main_skips_runtime_dependency_validation_when_update_handoff_starts(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, capture_mode="system-proxy", output_root=Path("output"), output_path=None)
        with (
            mock.patch.object(nct.sys, "platform", "win32"),
            mock.patch.object(nct, "handle_early_update_request", return_value=None),
            mock.patch.object(nct_config, "load_stable_config_snapshot", return_value=(dict(nct_config.DEFAULT_CONFIG), None)),
            mock.patch.object(nct_config, "resolve_runtime_options", return_value=options),
            mock.patch.object(elevation, "is_elevated", return_value=True),
            mock.patch.object(elevation, "elevation_task_is_current", return_value=True),
            mock.patch.object(nct, "capture_lock", side_effect=contextlib.nullcontext),
            mock.patch.object(nct, "handle_automatic_update", return_value=0) as handle_update,
            mock.patch.object(nct, "validate_mitmproxy_installation") as validate_runtime,
            mock.patch.object(nct, "validate_windows_capture_package") as validate_windows,
        ):
            self.assertEqual(nct.main([]), 0)
        handle_update.assert_called_once()
        validate_runtime.assert_not_called()
        validate_windows.assert_not_called()

    def test_updater_releases_capture_install_lock_before_relaunch(self) -> None:
        events: list[str] = []
        @contextlib.contextmanager
        def updater_lock(*args, **kwargs):
            events.append("updater-enter")
            try:
                yield
            finally:
                events.append("updater-exit")
        @contextlib.contextmanager
        def capture_lock(*args, **kwargs):
            events.append("capture-enter")
            try:
                yield
            finally:
                events.append("capture-exit")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install = root / "install"
            stage = install / "temp" / ("update_" + "a" * 32) / "stage"
            backup = stage.parent / "backup_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            install.mkdir(parents=True)
            stage.mkdir(parents=True)
            backup.mkdir()
            executable = install / "NinjaCaptureTool.exe"
            with (
                mock.patch.object(update.sys, "platform", "win32"),
                mock.patch.object(update, "write_update_session"),
                mock.patch.object(update, "wait_for_process_exit"),
                mock.patch.object(update, "updater_install_lock", side_effect=updater_lock),
                mock.patch.object(update, "capture_install_lock", side_effect=capture_lock),
                mock.patch.object(update, "installed_executable_satisfies_target", return_value=None),
                mock.patch.object(update, "install_staged_release", side_effect=lambda *args, **kwargs: (events.append("install") or (backup, []))),
                mock.patch.object(update, "validate_installed_executable", side_effect=lambda *args: events.append("validate")),
                mock.patch.object(update, "mark_update_session_committed", side_effect=lambda *args: events.append("commit")),
                mock.patch.object(update, "relaunch", side_effect=lambda *args: events.append("relaunch")),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                result = update.run_update_installer([
                    "--install-dir", str(install),
                    "--stage-dir", str(stage),
                    "--parent-pid", "123",
                    "--target-version", "1.1.0",
                    "--relaunch-executable", str(executable),
                    "--relaunch-cwd", str(root),
                ])
            self.assertEqual(result, 0)
        self.assertLess(events.index("capture-enter"), events.index("install"))
        self.assertLess(events.index("validate"), events.index("capture-exit"))
        self.assertLess(events.index("validate"), events.index("commit"))
        self.assertLess(events.index("commit"), events.index("capture-exit"))
        self.assertLess(events.index("capture-exit"), events.index("updater-exit"))
        self.assertLess(events.index("updater-exit"), events.index("relaunch"))

    def test_updater_defers_immediately_when_another_capture_is_active(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install = root / "install"
            stage = install / "temp" / ("update_" + "a" * 32) / "stage"
            install.mkdir(parents=True)
            stage.mkdir(parents=True)
            executable = install / "NinjaCaptureTool.exe"
            stdout = io.StringIO()
            with (
                mock.patch.object(update.sys, "platform", "win32"),
                mock.patch.object(update, "write_update_session"),
                mock.patch.object(update, "wait_for_process_exit"),
                mock.patch.object(update, "updater_install_lock", return_value=contextlib.nullcontext()),
                mock.patch.object(update, "capture_install_lock", side_effect=update.CaptureActiveError("active")),
                mock.patch.object(update, "install_staged_release") as install_release,
                mock.patch.object(update, "cleanup_deferred_update_payload") as cleanup_deferred,
                mock.patch.object(update, "relaunch") as relaunch,
                contextlib.redirect_stdout(stdout),
            ):
                result = update.run_update_installer([
                    "--install-dir", str(install),
                    "--stage-dir", str(stage),
                    "--parent-pid", "123",
                    "--target-version", "1.1.0",
                    "--relaunch-executable", str(executable),
                    "--relaunch-cwd", str(root),
                ])
            self.assertEqual(result, 0)
            self.assertIn("Installation deferred", stdout.getvalue())
            install_release.assert_not_called()
            cleanup_deferred.assert_called_once_with(stage.parent, install)
            relaunch.assert_not_called()

    def test_updater_does_not_relaunch_while_another_updater_is_active(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install = root / "install"
            stage = install / "temp" / ("update_" + "a" * 32) / "stage"
            install.mkdir(parents=True)
            stage.mkdir(parents=True)
            executable = install / "NinjaCaptureTool.exe"
            with (
                mock.patch.object(update.sys, "platform", "win32"),
                mock.patch.object(update, "write_update_session"),
                mock.patch.object(update, "wait_for_process_exit"),
                mock.patch.object(update, "updater_install_lock", side_effect=update.UpdaterBusyError("busy")),
                mock.patch.object(update, "cleanup_deferred_update_payload") as cleanup_deferred,
                mock.patch.object(update, "relaunch") as relaunch,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                result = update.run_update_installer([
                    "--install-dir", str(install),
                    "--stage-dir", str(stage),
                    "--parent-pid", "123",
                    "--target-version", "1.1.0",
                    "--relaunch-executable", str(executable),
                    "--relaunch-cwd", str(root),
                ])
            self.assertEqual(result, 0)
            cleanup_deferred.assert_called_once_with(stage.parent, install)
            relaunch.assert_not_called()

    def test_deferred_update_cleanup_preserves_redirected_work_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install = root / "install"
            temp_root = install / "temp"
            external = root / "external"
            install.mkdir()
            temp_root.mkdir()
            external.mkdir()
            marker = external / "keep.txt"
            marker.write_text("keep", encoding="utf-8")
            work = temp_root / "update_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            try:
                work.symlink_to(external, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"Directory symlink creation is unavailable: {exc}")
            update.cleanup_deferred_update_payload(work, install)
            self.assertEqual(marker.read_text(encoding="utf-8"), "keep")

    def test_updater_rejects_workspace_outside_install_temp_before_any_install_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install = root / "install"
            stage = root / "external" / ("update_" + "a" * 32) / "stage"
            install.mkdir(parents=True)
            stage.mkdir(parents=True)
            marker = install / "keep.txt"
            marker.write_text("keep", encoding="utf-8")
            executable = install / "NinjaCaptureTool.exe"
            stderr = io.StringIO()
            with (
                mock.patch.object(update.sys, "platform", "win32"),
                mock.patch.object(update, "updater_install_lock") as updater_lock,
                mock.patch.object(update, "capture_install_lock") as capture_lock,
                mock.patch.object(update, "install_staged_release") as install_release,
                contextlib.redirect_stderr(stderr),
            ):
                result = update.run_update_installer([
                    "--install-dir", str(install),
                    "--stage-dir", str(stage),
                    "--parent-pid", "123",
                    "--target-version", "1.1.0",
                    "--relaunch-executable", str(executable),
                    "--relaunch-cwd", str(root),
                ])
            self.assertEqual(result, 1)
            self.assertEqual(marker.read_text(encoding="utf-8"), "keep")
            updater_lock.assert_not_called()
            capture_lock.assert_not_called()
            install_release.assert_not_called()
            self.assertIn("outside Ninja Capture Tool's temp directory", stderr.getvalue())

    def test_updater_rejects_cross_volume_workspace_before_install_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install = root / "install"
            stage = install / "temp" / ("update_" + "b" * 32) / "stage"
            install.mkdir(parents=True)
            stage.mkdir(parents=True)
            original_stat = Path.stat

            def fake_stat(path, *args, **kwargs):
                result = original_stat(path, *args, **kwargs)
                if path == install:
                    return SimpleNamespace(
                        st_dev=1,
                        st_mode=result.st_mode,
                        st_file_attributes=getattr(result, "st_file_attributes", 0),
                    )
                if path == stage:
                    return SimpleNamespace(
                        st_dev=2,
                        st_mode=result.st_mode,
                        st_file_attributes=getattr(result, "st_file_attributes", 0),
                    )
                return result

            with mock.patch.object(Path, "stat", autospec=True, side_effect=fake_stat):
                with self.assertRaisesRegex(RuntimeError, "same drive"):
                    update._validate_update_workspace(stage, install)

    def test_updater_install_lock_is_installation_scoped_filesystem_lock(self) -> None:
        fake_msvcrt = SimpleNamespace(
            LK_NBLCK=1,
            LK_UNLCK=2,
            locking=mock.MagicMock(),
        )
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(sys.modules, {"msvcrt": fake_msvcrt}):
            install = Path(tmp)
            with update.updater_install_lock(install):
                self.assertTrue(update.updater_install_lock_path(install).is_file())
        self.assertEqual(fake_msvcrt.locking.call_count, 2)
        self.assertEqual(fake_msvcrt.locking.call_args_list[0].args[1:], (fake_msvcrt.LK_NBLCK, 1))
        self.assertEqual(fake_msvcrt.locking.call_args_list[1].args[1:], (fake_msvcrt.LK_UNLCK, 1))

    @unittest.skipUnless(os.name == "nt", "Windows updater installation-lock test")
    def test_updater_install_lock_rejects_same_target_concurrently(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            errors: list[Exception] = []

            def contend() -> None:
                try:
                    with update.updater_install_lock(path, timeout_seconds=0):
                        pass
                except Exception as exc:
                    errors.append(exc)

            with update.updater_install_lock(path, timeout_seconds=0):
                thread = threading.Thread(target=contend)
                thread.start()
                thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], update.UpdaterBusyError)
            self.assertRegex(str(errors[0]), "already in progress")

    @unittest.skipUnless(os.name == "nt", "Windows updater installation-lock test")
    def test_updater_install_lock_can_be_reacquired_after_release(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            with update.updater_install_lock(path, timeout_seconds=0):
                pass
            with update.updater_install_lock(path, timeout_seconds=0):
                pass

    def test_updater_rejects_reparse_destination_hierarchy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install = root / "install"
            stage = root / "work" / "stage"
            external = root / "external"
            install.mkdir()
            stage.mkdir(parents=True)
            external.mkdir()
            try:
                (install / "data").symlink_to(external, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"Directory symlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(RuntimeError, "symlink, junction, or reparse point"):
                update.install_staged_release(stage, install, common.VERSION)
            self.assertEqual(list(external.iterdir()), [])

    def test_updater_rejects_symlink_inside_staged_release_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install = root / "install"
            stage = root / "stage"
            external = root / "external.bin"
            install.mkdir()
            stage.mkdir()
            (install / "keep.txt").write_text("keep", encoding="utf-8")
            (stage / "NinjaCaptureTool.exe").write_bytes(b"new")
            self._write_stage_release_manifest(stage)
            external.write_bytes(b"external")
            try:
                (stage / "linked.bin").symlink_to(external)
            except OSError as exc:
                self.skipTest(f"File symlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(RuntimeError, "symlink, junction, or reparse point"):
                update.install_staged_release(stage, install, common.VERSION)
            self.assertEqual((install / "keep.txt").read_text(encoding="utf-8"), "keep")
            self.assertFalse(any(path.name.startswith("backup_") for path in stage.parent.iterdir()))

    def test_updater_reparse_attribute_is_detected(self) -> None:
        self.assertTrue(update._is_reparse_stat(SimpleNamespace(st_file_attributes=0x400)))
        self.assertFalse(update._is_reparse_stat(SimpleNamespace(st_file_attributes=0)))

    def test_stale_update_recovery_backups_are_reported_but_never_deleted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp_root = Path(tmp) / "temp"
            work = temp_root / "update_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            backup = work / "backup_cccccccccccccccccccccccccccccccc"
            backup.mkdir(parents=True)
            (backup / "NinjaCaptureTool.exe").write_bytes(b"old")
            old = time.time() - (7 * 24 * 60 * 60) - 60
            os.utime(work, (old, old))
            with (
                mock.patch.object(update, "TOOL_DIR", Path(tmp)),
                mock.patch.object(update, "TEMP_ROOT", temp_root),
            ):
                update.cleanup_stale_update_work()
                self.assertEqual(update.stale_update_recovery_backups(), [work])
            self.assertTrue(work.is_dir())
            self.assertTrue(backup.is_dir())

    def test_stale_committed_update_backup_is_cleanup_debris_not_recovery_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp_root = Path(tmp) / "temp"
            work = temp_root / "update_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            backup = work / "backup_cccccccccccccccccccccccccccccccc"
            backup.mkdir(parents=True)
            (backup / "NinjaCaptureTool.exe").write_bytes(b"old")
            (work / update.UPDATE_SESSION_FILE).write_text(
                json.dumps(
                    {
                        "pid": 1234,
                        "process_identity": "1234:5678",
                        "transaction_state": "committed",
                    }
                ),
                encoding="utf-8",
            )
            old = time.time() - (7 * 24 * 60 * 60) - 60
            os.utime(work, (old, old))
            with (
                mock.patch.object(update, "TOOL_DIR", Path(tmp)),
                mock.patch.object(update, "TEMP_ROOT", temp_root),
            ):
                self.assertEqual(update.stale_update_recovery_backups(), [])
                update.cleanup_stale_update_work()
            self.assertFalse(work.exists())
            self.assertFalse(temp_root.exists())

    def test_update_temp_root_rejects_redirected_directory_before_payload_work(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install = root / "install"
            external = root / "external"
            install.mkdir()
            external.mkdir()
            temp_root = install / "temp"
            try:
                temp_root.symlink_to(external, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"Directory symlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(RuntimeError, "symlink, junction, or reparse point"):
                update._validate_update_temp_root(temp_root, install)

    def test_automatic_update_validates_temp_before_copy_download_or_extract(self) -> None:
        args = SimpleNamespace(no_auto_update=False, auto_update=True)
        release = {"version": "1.2.0", "assets": [], "url": "https://github.com/example/release"}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            temp_root = root / "temp"
            with (
                mock.patch.object(update.sys, "frozen", True, create=True),
                mock.patch.object(update, "TOOL_DIR", root),
                mock.patch.object(update, "TEMP_ROOT", temp_root),
                mock.patch.object(update, "check_for_update", return_value=release),
                mock.patch.object(update, "_record_update_check_result"),
                mock.patch.object(update, "_validate_update_temp_root", side_effect=RuntimeError("redirected temp")) as validate_temp,
                mock.patch.object(update, "_copy_application_for_update") as copy_updater,
                mock.patch.object(update, "download_release") as download,
                mock.patch.object(update, "extract_release_archive") as extract,
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertIsNone(update.handle_automatic_update(args, [], True))
            validate_temp.assert_called_once_with(temp_root, root)
            copy_updater.assert_not_called()
            download.assert_not_called()
            extract.assert_not_called()
            self.assertFalse(temp_root.exists())

    def test_updater_revalidates_workspace_inside_locks_before_install_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install = root / "install"
            stage = install / "temp" / ("update_" + "c" * 32) / "stage"
            install.mkdir(parents=True)
            stage.mkdir(parents=True)
            marker_file = install / "keep.txt"
            marker_file.write_text("keep", encoding="utf-8")
            executable = install / "NinjaCaptureTool.exe"
            stderr = io.StringIO()
            with (
                mock.patch.object(update.sys, "platform", "win32"),
                mock.patch.object(update, "_validate_update_workspace", side_effect=[(install, stage), RuntimeError("workspace changed")]) as validate_workspace,
                mock.patch.object(update, "write_update_session"),
                mock.patch.object(update, "wait_for_process_exit"),
                mock.patch.object(update, "updater_install_lock", return_value=contextlib.nullcontext()),
                mock.patch.object(update, "capture_install_lock", return_value=contextlib.nullcontext()),
                mock.patch.object(update, "installed_executable_satisfies_target") as installed_version,
                mock.patch.object(update, "install_staged_release") as install_release,
                mock.patch.object(update, "relaunch") as relaunch,
                mock.patch.object(update, "_update_work_has_backup", return_value=False),
                contextlib.redirect_stderr(stderr),
            ):
                result = update.run_update_installer([
                    "--install-dir", str(install),
                    "--stage-dir", str(stage),
                    "--parent-pid", "123",
                    "--target-version", "1.1.0",
                    "--relaunch-executable", str(executable),
                    "--relaunch-cwd", str(root),
                ])
            self.assertEqual(result, 1)
            self.assertEqual(validate_workspace.call_count, 2)
            installed_version.assert_not_called()
            install_release.assert_not_called()
            relaunch.assert_called_once()
            self.assertEqual(marker_file.read_text(encoding="utf-8"), "keep")
            self.assertIn("workspace changed", stderr.getvalue())

    def test_updater_publishes_runtime_manifest_and_executable_last(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install = root / "install"
            stage = root / "temp" / "update_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" / "stage"
            install.mkdir(parents=True)
            (install / common.FROZEN_RUNTIME_DIR_NAME).mkdir()
            (install / common.FROZEN_RUNTIME_DIR_NAME / "old.dll").write_bytes(b"old-runtime")
            (install / "NinjaCaptureTool.exe").write_bytes(b"old-exe")
            (stage / common.FROZEN_RUNTIME_DIR_NAME).mkdir(parents=True)
            (stage / common.FROZEN_RUNTIME_DIR_NAME / "python314.dll").write_bytes(b"new-runtime")
            (stage / "NinjaCaptureTool.exe").write_bytes(b"new-exe")
            (stage / "README.txt").write_text("new readme", encoding="utf-8")
            self._write_stage_release_manifest(stage)

            published: list[str] = []
            original_publish = update._publish_staged_item

            def publish(source: Path, destination: Path) -> None:
                published.append(source.relative_to(stage).as_posix())
                original_publish(source, destination)

            with (
                mock.patch.object(update, "_publish_staged_item", side_effect=publish),
                mock.patch.object(update.shutil, "copy2") as copy2,
                mock.patch.object(update.shutil, "copytree") as copytree,
            ):
                backup, changes = update.install_staged_release(stage, install, common.VERSION)

            copy2.assert_not_called()
            copytree.assert_not_called()
            self.assertEqual(
                published[-3:],
                [common.FROZEN_RUNTIME_DIR_NAME, common.RELEASE_MANIFEST_FILE, "NinjaCaptureTool.exe"],
            )
            self.assertFalse((stage / common.FROZEN_RUNTIME_DIR_NAME).exists())
            self.assertFalse((stage / common.RELEASE_MANIFEST_FILE).exists())
            self.assertFalse((stage / "NinjaCaptureTool.exe").exists())
            self.assertEqual((install / common.FROZEN_RUNTIME_DIR_NAME / "python314.dll").read_bytes(), b"new-runtime")
            self.assertEqual((install / "NinjaCaptureTool.exe").read_bytes(), b"new-exe")

            update.rollback_staged_release(changes, backup)
            self.assertEqual((install / common.FROZEN_RUNTIME_DIR_NAME / "old.dll").read_bytes(), b"old-runtime")
            self.assertEqual((install / "NinjaCaptureTool.exe").read_bytes(), b"old-exe")

    def test_updater_rolls_back_every_staged_publication_failure(self) -> None:
        def snapshot_tree(root: Path) -> dict[str, tuple[str, bytes | None]]:
            snapshot: dict[str, tuple[str, bytes | None]] = {}
            for path in sorted(root.rglob("*"), key=lambda item: item.as_posix().casefold()):
                relative = path.relative_to(root).as_posix()
                if path.is_dir():
                    snapshot[relative] = ("dir", None)
                else:
                    snapshot[relative] = ("file", path.read_bytes())
            return snapshot

        def build_case(root: Path) -> tuple[Path, Path]:
            install = root / "install"
            stage = root / "temp" / "update_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" / "stage"
            (install / common.FROZEN_RUNTIME_DIR_NAME).mkdir(parents=True)
            (install / common.FROZEN_RUNTIME_DIR_NAME / "old.dll").write_bytes(b"old-runtime")
            (install / "NinjaCaptureTool.exe").write_bytes(b"old-exe")
            (install / "README.txt").write_text("old readme", encoding="utf-8")
            (install / "data" / "licenses").mkdir(parents=True)
            (install / "data" / "licenses" / "old.txt").write_text("old license", encoding="utf-8")

            (stage / common.FROZEN_RUNTIME_DIR_NAME).mkdir(parents=True)
            (stage / common.FROZEN_RUNTIME_DIR_NAME / "python314.dll").write_bytes(b"new-runtime")
            (stage / "NinjaCaptureTool.exe").write_bytes(b"new-exe")
            (stage / "README.txt").write_text("new readme", encoding="utf-8")
            (stage / "data" / "licenses").mkdir(parents=True)
            (stage / "data" / "licenses" / "new.txt").write_text("new license", encoding="utf-8")
            self._write_stage_release_manifest(stage)
            return install, stage

        with tempfile.TemporaryDirectory() as tmp:
            install, stage = build_case(Path(tmp))
            publish_count = 0
            original_publish = update._publish_staged_item

            def count_publish(source: Path, destination: Path) -> None:
                nonlocal publish_count
                publish_count += 1
                original_publish(source, destination)

            with mock.patch.object(update, "_publish_staged_item", side_effect=count_publish):
                backup, changes = update.install_staged_release(stage, install, common.VERSION)
            update.rollback_staged_release(changes, backup)

        self.assertGreater(publish_count, 0)
        for fail_at in range(1, publish_count + 1):
            with self.subTest(fail_at=fail_at), tempfile.TemporaryDirectory() as tmp:
                install, stage = build_case(Path(tmp))
                before = snapshot_tree(install)
                original_publish = update._publish_staged_item
                publication = 0

                def fail_publish(source: Path, destination: Path) -> None:
                    nonlocal publication
                    publication += 1
                    if publication == fail_at:
                        raise RuntimeError(f"injected publication failure {fail_at}")
                    original_publish(source, destination)

                with (
                    mock.patch.object(update, "_publish_staged_item", side_effect=fail_publish),
                    self.assertRaisesRegex(RuntimeError, f"injected publication failure {fail_at}"),
                ):
                    update.install_staged_release(stage, install, common.VERSION)

                self.assertEqual(snapshot_tree(install), before)
                self.assertFalse(
                    any(update._UPDATE_BACKUP_NAME_RE.fullmatch(path.name) for path in stage.parent.iterdir())
                )

    def test_updater_rolls_back_when_published_file_changes_before_post_install_verification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install = root / "install"
            stage = root / "temp" / "update_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" / "stage"
            install.mkdir(parents=True)
            (install / "NinjaCaptureTool.exe").write_bytes(b"old-exe")
            (install / "README.txt").write_text("old readme", encoding="utf-8")
            stage.mkdir(parents=True)
            (stage / "NinjaCaptureTool.exe").write_bytes(b"new-exe")
            (stage / "README.txt").write_text("new readme", encoding="utf-8")
            self._write_stage_release_manifest(stage)

            original_publish = update._publish_staged_item

            def publish_then_tamper(source: Path, destination: Path) -> None:
                original_publish(source, destination)
                if destination.name == "README.txt":
                    destination.write_text("tampered after staged validation", encoding="utf-8")

            with (
                mock.patch.object(update, "_publish_staged_item", side_effect=publish_then_tamper),
                self.assertRaisesRegex(RuntimeError, "Installed release SHA-256 does not match 'README.txt'"),
            ):
                update.install_staged_release(stage, install, common.VERSION)

            self.assertEqual((install / "NinjaCaptureTool.exe").read_bytes(), b"old-exe")
            self.assertEqual((install / "README.txt").read_text(encoding="utf-8"), "old readme")
            self.assertFalse((install / common.RELEASE_MANIFEST_FILE).exists())
            self.assertFalse(
                any(update._UPDATE_BACKUP_NAME_RE.fullmatch(path.name) for path in stage.parent.iterdir())
            )

    def test_publish_staged_item_rejects_cross_volume_or_failed_rename_without_copy_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.bin"
            destination = root / "nested" / "destination.bin"
            source.write_bytes(b"payload")
            with (
                mock.patch.object(Path, "rename", side_effect=OSError("cross-device link")) as rename,
                mock.patch.object(Path, "replace") as replace,
            ):
                with self.assertRaisesRegex(RuntimeError, "same-volume rename"):
                    update._publish_staged_item(source, destination)
            rename.assert_called_once_with(destination)
            replace.assert_not_called()
            self.assertTrue(source.exists())
            self.assertFalse(destination.exists())

    def test_startup_warns_about_stale_preserved_update_backup_path(self) -> None:
        work = Path("D:/Ninja Capture Tool/temp/update_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        stderr = io.StringIO()
        with (
            mock.patch.object(nct, "stale_update_recovery_backups", return_value=[work]),
            mock.patch.object(nct_runtime, "show_console_window") as show_console,
            contextlib.redirect_stderr(stderr),
        ):
            nct._warn_stale_update_recovery_backups()
        show_console.assert_called_once_with()
        self.assertIn("Preserved updater recovery data", stderr.getvalue())
        self.assertIn(str(work), stderr.getvalue())
