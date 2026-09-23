# Run from the project root with: py -B -m unittest discover -s tests
from support import *

class SessionTests(NctTestBase):
    def test_console_status_colors_are_restrained_and_semantic(self) -> None:
        stream = io.StringIO()
        message = (
            "[Saved] 3 B | 200 | /a.bin\n"
            "[Saved] 0 B | OK | /0/UNMANAGED\n"
            "[Skipped] 3 B | 206 | /b.bin\n"
            "[Skipped] 0 B | 302 | /c.bin\n"
            "[Skipped] 0 B | 404 | /d.bin\n"
            "[Extracted] 4 B | MD5 OK | Warframe.x64.exe\n"
            "[Saving] 2.5 MiB / 5.7 MiB (43.9%) | 3.0 MiB/s | /large.bin\n"
            "[Extracting] 20.0 MiB / 40.0 MiB (50.0%) | 80.0 MiB/s | Warframe.x64.exe\n"
            "[Update] 30.0 MiB / 60.0 MiB (50.0%) | 6.0 MiB/s | NinjaCaptureTool-v1.1.0-Windows-x64.zip\n"
            "[Waiting] 2.0 GiB needed / 1.0 GiB available | Free disk space to continue | /large.bin\n"
            "[Debug] Skipped HTTP 503: /broken\n"
            "WARNING: warning\n"
            "ERROR: error\n"
            "[Proxy] WARNING: proxy warning\n"
            "[Proxy] ERROR: proxy error"
        )
        with mock.patch.object(common, "console_supports_color", return_value=True):
            styled = common.style_console_text(message, stream, status_tokens=True)
        self.assertIn("\x1b[32m200\x1b[0m", styled)
        self.assertIn("\x1b[32mOK\x1b[0m", styled)
        self.assertIn("\x1b[33m206\x1b[0m", styled)
        self.assertIn("\x1b[33m302\x1b[0m", styled)
        self.assertIn("\x1b[31m404\x1b[0m", styled)
        self.assertIn("\x1b[32mMD5 OK\x1b[0m", styled)
        self.assertIn(
            "[Saving] \x1b[36m2.5 MiB / 5.7 MiB (43.9%)\x1b[0m | 3.0 MiB/s | /large.bin",
            styled,
        )
        self.assertNotIn("\x1b[36m[Saving]", styled)
        self.assertIn(
            "[Extracting] \x1b[36m20.0 MiB / 40.0 MiB (50.0%)\x1b[0m | 80.0 MiB/s | Warframe.x64.exe",
            styled,
        )
        self.assertNotIn("\x1b[36m[Extracting]", styled)
        self.assertIn(
            "[Update] \x1b[36m30.0 MiB / 60.0 MiB (50.0%)\x1b[0m | 6.0 MiB/s | NinjaCaptureTool-v1.1.0-Windows-x64.zip",
            styled,
        )
        self.assertNotIn("\x1b[36m[Update]", styled)
        self.assertIn(
            "[Waiting] \x1b[36m2.0 GiB needed / 1.0 GiB available\x1b[0m | Free disk space to continue | /large.bin",
            styled,
        )
        self.assertNotIn("\x1b[36m[Waiting]", styled)
        self.assertIn("HTTP \x1b[31m503\x1b[0m: /broken", styled)
        self.assertIn("\x1b[33mWARNING:\x1b[0m", styled)
        self.assertIn("\x1b[31mERROR:\x1b[0m", styled)
        self.assertIn("[Proxy] \x1b[33mWARNING:\x1b[0m proxy warning", styled)
        self.assertIn("[Proxy] \x1b[31mERROR:\x1b[0m proxy error", styled)
        self.assertNotIn("\x1b[31m[Proxy]", styled)
        self.assertNotIn("\x1b[33m[Proxy]", styled)
        self.assertIn("[Saved]", styled)
        self.assertNotIn("\x1b[32m[Saved]", styled)

    def test_console_colors_are_disabled_for_non_tty_output(self) -> None:
        message = "ERROR: failure | 500 | MD5 OK"
        self.assertEqual(common.style_console_text(message, io.StringIO(), status_tokens=True), message)

    def test_local_capture_runtime_root_uses_canonical_local_app_data_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "DarkLotus" / "Ninja Capture Tool"
            with mock.patch.object(nct, "nct_local_app_data_root", return_value=root):
                self.assertEqual(
                    nct._local_capture_runtime_root(),
                    root / "runtime" / "mitmproxy-windows",
                )

    def test_local_capture_runtime_cleanup_skips_all_old_runtimes_while_windivert_is_loaded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            current = root / "current"
            old_a = root / "old-a"
            old_b = root / "old-b"
            current.mkdir()
            old_a.mkdir()
            old_b.mkdir()
            (old_a / "windows-redirector.exe").write_bytes(b"old")
            (old_a / "WinDivert64.sys").write_bytes(b"driver")
            (old_b / "WinDivert64.sys").write_bytes(b"driver")

            with (
                mock.patch.object(nct, "_windivert_driver_loaded", return_value=True),
                mock.patch.object(nct, "_remove_local_capture_runtime_path") as remove,
            ):
                nct._cleanup_old_local_capture_runtimes(root, current)

            remove.assert_not_called()
            self.assertTrue(current.is_dir())
            self.assertTrue((old_a / "windows-redirector.exe").is_file())
            self.assertTrue((old_a / "WinDivert64.sys").is_file())
            self.assertTrue((old_b / "WinDivert64.sys").is_file())

    def test_invalid_current_local_capture_runtime_is_left_untouched_while_windivert_is_loaded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "release-runtime"
            source.mkdir()
            payloads = {
                "windows-redirector.exe": b"redirector-v1",
                "WinDivert.dll": b"dll-v1",
                "WinDivert64.sys": b"driver-v1",
            }
            for name, payload in payloads.items():
                (source / name).write_bytes(payload)
            sources = tuple(source / name for name in payloads)
            fingerprint = nct._local_capture_runtime_fingerprint(sources)
            runtime_root = root / "localappdata-runtime"
            destination = runtime_root / f"{common.MITMPROXY_VERSION}-{fingerprint}"
            destination.mkdir(parents=True)
            for name, payload in payloads.items():
                (destination / name).write_bytes(payload)
            damaged = destination / "windows-redirector.exe"
            damaged.write_bytes(b"damaged")
            module = ModuleType("mitmproxy_windows")
            module.executable_path = lambda: source / "windows-redirector.exe"
            with (
                mock.patch.object(nct.sys, "platform", "win32"),
                mock.patch.dict(sys.modules, {"mitmproxy_windows": module}),
                mock.patch.object(nct, "_local_capture_runtime_root", return_value=runtime_root),
                mock.patch.object(nct, "_windivert_driver_loaded", return_value=True),
                mock.patch.object(nct, "_remove_local_capture_runtime_path") as remove,
            ):
                with self.assertRaisesRegex(RuntimeError, "invalid while WinDivert is still loaded"):
                    nct.prepare_windows_local_capture_runtime()
            remove.assert_not_called()
            self.assertEqual(damaged.read_bytes(), b"damaged")
            self.assertEqual((destination / "WinDivert.dll").read_bytes(), b"dll-v1")
            self.assertEqual((destination / "WinDivert64.sys").read_bytes(), b"driver-v1")

    def test_local_capture_runtime_cleanup_removes_old_runtime_when_windivert_is_not_loaded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            current = root / "current"
            old_runtime = root / "old"
            current.mkdir()
            old_runtime.mkdir()
            (old_runtime / "WinDivert64.sys").write_bytes(b"driver")
            with mock.patch.object(nct, "_windivert_driver_loaded", return_value=False):
                nct._cleanup_old_local_capture_runtimes(root, current)
            self.assertTrue(current.is_dir())
            self.assertFalse(old_runtime.exists())

    def test_local_capture_runtime_requires_windivert_driver_next_to_redirector(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp)
            (source / "windows-redirector.exe").write_bytes(b"redirector")
            (source / "WinDivert.dll").write_bytes(b"dll")
            module = ModuleType("mitmproxy_windows")
            module.executable_path = lambda: source / "windows-redirector.exe"
            with (
                mock.patch.object(nct.sys, "platform", "win32"),
                mock.patch.dict(sys.modules, {"mitmproxy_windows": module}),
                mock.patch.object(nct, "_local_capture_runtime_root", return_value=source / "external"),
            ):
                with self.assertRaisesRegex(RuntimeError, "WinDivert64\\.sys"):
                    nct.prepare_windows_local_capture_runtime()

    def test_process_monitor_detection_covers_official_executable_names(self) -> None:
        for name in ("Procmon.exe", "Procmon64.exe", "Procmon64a.exe"):
            with (
                self.subTest(name=name),
                mock.patch.object(nct.sys, "platform", "win32"),
                mock.patch.object(nct_runtime, "running_process_names", return_value={name.casefold()}),
            ):
                self.assertTrue(nct_runtime.process_monitor_is_running())

    def test_local_capture_preflight_rejects_process_monitor(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG)
        with mock.patch.object(nct_runtime, "process_monitor_is_running", return_value=True):
            with self.assertRaisesRegex(RuntimeError, "Process Monitor is running"):
                nct_runtime.ensure_local_capture_compatible(options)

    def test_live_process_change_shows_current_list_and_restarts_worker(self) -> None:
        args = nct_config.build_argument_parser().parse_args([])
        options = nct_config.resolve_runtime_options(args, dict(nct_config.DEFAULT_CONFIG))
        session = nct.CaptureSession(options, cli_args=args)
        config = dict(nct_config.DEFAULT_CONFIG)
        config["processes"] = ["Launcher.exe", "OtherGame.exe"]
        output = io.StringIO()
        with (
            mock.patch.object(session, "_restart_worker_for_options") as restart_worker,
            contextlib.redirect_stdout(output),
        ):
            self.assertFalse(session._apply_reloaded_config(config))
        restart_worker.assert_called_once()
        text = output.getvalue()
        self.assertIn("[Config] Change detected.", text)
        self.assertIn("[Config] Processes: Launcher.exe, OtherGame.exe", text)
        self.assertNotIn("Old:", text)
        self.assertNotIn("New:", text)
        self.assertIn("Restarting capture worker to apply changes...", text)
        self.assertIn("Capture worker restarted successfully.", text)
        self.assertTrue(text.endswith("\n\n"))

    def test_worker_output_is_queued_until_restart_status_is_complete(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG)
        session = nct.CaptureSession(options)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            session._hold_worker_output()
            session.log("Restarting capture worker to apply changes...")
            session._queue_worker_output("[Debug] https://example.com/ (ignored)")
            session.log("Capture worker restarted successfully.")
            session._release_worker_output()

        lines = output.getvalue().splitlines()
        self.assertEqual(lines[0], "Restarting capture worker to apply changes...")
        self.assertEqual(lines[1], "Capture worker restarted successfully.")
        self.assertEqual(lines[2], "[Debug] https://example.com/ (ignored)")

    def test_urgent_worker_output_uses_fifo_ahead_of_console_backlog(self) -> None:
        session = nct.CaptureSession(dict(nct_config.DEFAULT_CONFIG))
        session.worker_console_queue.extend(["[Debug] one", "[Debug] two"])
        with mock.patch.object(session, "_start_worker_console_dispatcher"):
            session._queue_worker_output("[Proxy] WARNING: first")
            session._queue_worker_output("ERROR: second")
            session._queue_worker_output("WARNING: third")
        self.assertEqual(
            list(session.worker_console_urgent_queue),
            ["[Proxy] WARNING: first", "ERROR: second", "WARNING: third"],
        )
        self.assertEqual(list(session.worker_console_queue), ["[Debug] one", "[Debug] two"])

    def test_worker_console_backlog_retains_newest_ordinary_lines(self) -> None:
        session = nct.CaptureSession(dict(nct_config.DEFAULT_CONFIG))
        session.worker_console_queue.extend(f"[Debug] old {index}" for index in range(2048))
        with mock.patch.object(session, "_start_worker_console_dispatcher"):
            session._queue_worker_output("[Debug] newest")
        self.assertEqual(len(session.worker_console_queue), 2048)
        self.assertEqual(session.worker_console_queue[0], "[Debug] old 1")
        self.assertEqual(session.worker_console_queue[-1], "[Debug] newest")
        self.assertEqual(session.worker_console_dropped, 1)

    def test_live_worker_restart_keeps_ordinary_worker_output_after_success_line(self) -> None:
        args = nct_config.build_argument_parser().parse_args([])
        options = nct_config.resolve_runtime_options(args, dict(nct_config.DEFAULT_CONFIG))
        session = nct.CaptureSession(options, cli_args=args)
        config = dict(nct_config.DEFAULT_CONFIG)
        config["debug"] = True
        output = io.StringIO()

        def restart_with_early_debug(_new_options):
            session._queue_worker_output("[Debug] https://example.com/ (ignored)")

        with (
            mock.patch.object(session, "_restart_worker_for_options", side_effect=restart_with_early_debug),
            contextlib.redirect_stdout(output),
        ):
            self.assertFalse(session._apply_reloaded_config(config))

        text = output.getvalue()
        self.assertLess(text.index("Restarting capture worker to apply changes..."), text.index("Capture worker restarted successfully."))
        self.assertLess(text.index("Capture worker restarted successfully."), text.index("[Debug] https://example.com/ (ignored)"))

    def test_retiring_worker_suppresses_expected_event_loop_closed_spawn_race(self) -> None:
        session = nct.CaptureSession(dict(nct_config.DEFAULT_CONFIG))
        process = SimpleNamespace(
            stdout=io.StringIO(
                "Failed to spawn connection handler:\n"
                "RuntimeError: Event loop is closed\n"
                "[Debug] stale retiring-worker output\n"
            )
        )
        with session.worker_retirement_lock:
            session.retiring_worker_ids.add(id(process))
        with (
            mock.patch.object(session, "_set_worker_progress"),
            mock.patch.object(session, "_queue_worker_output") as queue_output,
        ):
            session._read_worker_output(process)

        queue_output.assert_called_once_with("[Debug] stale retiring-worker output")
        with session.worker_retirement_lock:
            self.assertNotIn(id(process), session.retiring_worker_ids)

    def test_live_worker_keeps_event_loop_closed_spawn_error_visible(self) -> None:
        session = nct.CaptureSession(dict(nct_config.DEFAULT_CONFIG))
        process = SimpleNamespace(
            stdout=io.StringIO(
                "Failed to spawn connection handler:\n"
                "RuntimeError: Event loop is closed\n"
            )
        )
        with (
            mock.patch.object(session, "_set_worker_progress"),
            mock.patch.object(session, "_queue_worker_output") as queue_output,
        ):
            session._read_worker_output(process)

        self.assertEqual(
            queue_output.call_args_list,
            [
                mock.call("[Proxy] Failed to spawn connection handler:"),
                mock.call("[Proxy] RuntimeError: Event loop is closed"),
            ],
        )

    def test_live_global_debug_change_restarts_worker_and_repeats_privacy_notice(self) -> None:
        args = nct_config.build_argument_parser().parse_args([])
        options = nct_config.resolve_runtime_options(args, dict(nct_config.DEFAULT_CONFIG))
        session = nct.CaptureSession(options, cli_args=args)
        config = dict(nct_config.DEFAULT_CONFIG)
        config["debug"] = "global"
        output = io.StringIO()
        with (
            mock.patch.object(session, "_restart_worker_for_options") as restart_worker,
            contextlib.redirect_stdout(output),
        ):
            self.assertFalse(session._apply_reloaded_config(config))
        restart_worker.assert_called_once()
        text = output.getvalue()
        self.assertIn("[Config] Debug: Off -> Global", text)
        self.assertIn("Global debug can log hostnames and IP addresses", text)
        self.assertIn("review the session capture log before sharing it.", text)
        self.assertNotIn("timestamped capture log", text)
        self.assertNotIn("[Privacy]", text)

    def test_worker_drain_stops_new_captures_and_finishes_existing_capture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            store = capture.CaptureStore(session, self.manifest_path_for(session), worker_protocol_enabled=True)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                writer = store.begin("https://content.warframe.com/large.bin", 200, 3)
                store.request_drain()
                with self.assertRaises(capture.CaptureDrainRequested):
                    store.begin("https://content.warframe.com/new.bin", 200, 1)
                writer.feed(b"abc")
                writer.feed(b"")
                store.close_metadata()
            messages = worker_messages(output.getvalue())
            self.assertIn({"type": "activity", "active": 1}, messages)
            self.assertIn({"type": "activity", "active": 0}, messages)
            self.assertIn({"type": "drained"}, messages)
            self.assertTrue((session / "OpenWF" / "Content" / "large.bin").is_file())
            self.assertFalse((session / "OpenWF" / "Content" / "new.bin").exists())

    def test_process_names_preserve_case_and_only_exact_duplicates_are_removed(self) -> None:
        self.assertEqual(
            nct_config.validate_processes(["Launcher.exe", "launcher.exe", "Launcher.exe", "Warframe.x64.exe"]),
            ["Launcher.exe", "launcher.exe", "Warframe.x64.exe"],
        )

    def test_global_debug_is_local_capture_only(self) -> None:
        config = dict(nct_config.DEFAULT_CONFIG, debug="global")
        args = nct_config.build_argument_parser().parse_args([])
        self.assertEqual(nct_config.resolve_runtime_options(args, config)["debug"], "global")
        args = nct_config.build_argument_parser().parse_args(["-m", "system-proxy", "-d", "global"])
        with self.assertRaisesRegex(RuntimeError, "Local Capture"):
            nct_config.resolve_runtime_options(args, nct_config.DEFAULT_CONFIG)

    def test_session_directories_are_timestamped_and_never_reused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            now = datetime(2026, 8, 24, 16, 10, 23, tzinfo=timezone.utc)
            first = common.create_session_directory(root, now)
            second = common.create_session_directory(root, now)
            self.assertEqual(first.name, "2026-08-24_16-10-23")
            self.assertEqual(second.name, "2026-08-24_16-10-23_2")
            self.assertFalse((first / "OpenWF").exists())

    def test_version_named_session_directories_are_unique_and_numeric(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = common.create_named_session_directory(root, "43.5.4")
            second = common.create_named_session_directory(root, "43.5.4")
            self.assertEqual(first.name, "43.5.4")
            self.assertEqual(second.name, "43.5.4_2")
            with self.assertRaisesRegex(RuntimeError, "Invalid automatic session name"):
                common.create_named_session_directory(root, "U43.5.4")

    def test_session_artifact_paths_use_timestamp_prefix(self) -> None:
        root = Path("C:/output")
        log_path, manifest_path = common.session_artifact_paths(root, "2026-08-24_16-10-23_2")
        self.assertEqual(log_path, root / "2026-08-24_16-10-23_2_capture.log")
        self.assertEqual(manifest_path, root / "2026-08-24_16-10-23_2_session.json")

    def test_session_directory_allocation_skips_existing_sidecar_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            now = datetime(2026, 8, 24, 16, 10, 23, tzinfo=timezone.utc)
            _, manifest_path = common.session_artifact_paths(root, "2026-08-24_16-10-23")
            manifest_path.write_text("{}", encoding="utf-8")
            session = common.create_session_directory(root, now)
            self.assertEqual(session.name, "2026-08-24_16-10-23_2")

    def test_automatic_session_keeps_diagnostics_beside_capture_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            session = nct.CaptureSession(options)
            with (
                mock.patch.object(windows_proxy, "restore_stale_recovery", return_value=None),
                mock.patch.object(common, "prepare_runtime_state_directory"),
                mock.patch.object(common, "prepare_output_directory", return_value=2 * 1024 * 1024 * 1024),
                mock.patch.object(common, "recover_stale_sessions", return_value=(0, [])),
                mock.patch.object(nct_runtime, "ensure_mitmproxy_ca_trusted", return_value=False),
                mock.patch.object(session, "_start_worker"),
                mock.patch.object(session, "_wait_for_worker_ready"),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                session.start()
            assert session.session_root is not None
            assert session.log_path is not None
            assert session.manifest_path is not None
            self.assertEqual(session.log_path, root / f"{session.session_root.name}_capture.log")
            self.assertEqual(session.manifest_path, root / f"{session.session_root.name}_session.json")
            self.assertEqual(common.read_json_object(session.manifest_path)["capture_directory"], session.session_root.name)
            self.assertFalse((session.session_root / "capture.log").exists())
            self.assertFalse((session.session_root / "session.json").exists())
            assert session.logger is not None
            session.logger.close()

    def test_h_cache_fetch_runs_once_per_session_after_b_cache_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp) / "session"
            session.mkdir()
            manifest_path = self.manifest_path_for(session)
            capture.initialize_session_manifest(session, nct_config.DEFAULT_CONFIG, manifest_path)
            store = capture.CaptureStore(session, manifest_path, debug=True)
            output = io.StringIO()
            with (
                mock.patch.object(store, "_fetch_official_h_cache") as fetch,
                contextlib.redirect_stdout(output),
            ):
                # Localized B.Cache manifests are enough to establish update activity.
                # The exact B.Cache.Windows.bin request is not guaranteed to occur.
                store.maybe_fetch_official_h_cache("/0/B.Cache.Windows_zh.bin!E_hash")
                assert store._h_cache_fetch_thread is not None
                store._h_cache_fetch_thread.join(timeout=1)
                store.maybe_fetch_official_h_cache("/0/B.Cache.Windows_xx.bin!E_other")
            fetch.assert_called_once_with("E")
            self.assertIn(
                "[Debug] Detected B.Cache.* activity. Acquiring H.Cache.bin for this update...",
                output.getvalue(),
            )

    def test_worker_restart_preserves_h_cache_conflict_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp) / "session"
            session.mkdir()
            manifest_path = self.manifest_path_for(session)
            capture.initialize_session_manifest(session, nct_config.DEFAULT_CONFIG, manifest_path)
            store = capture.CaptureStore(session, manifest_path)
            store._h_cache_fetch_started = True

            def save(target, path, body):
                writer = target.begin("https://content.warframe.com" + path, 200, len(body))
                writer.feed(body)
                writer.feed(b"")

            b_cache = "/0/B.Cache.Windows.bin!E_hash"
            h_cache = "/0/H.Cache.bin!E_---------------------w"
            body = make_shcc_container(b"first")
            save(store, b_cache, b"B.Cache")
            save(store, h_cache, body)
            unmanaged = session / "OpenWF" / "Content" / "0" / "UNMANAGED"
            self.assertTrue(unmanaged.exists())
            save(store, h_cache, make_shcc_container(b"different"))
            self.assertFalse(unmanaged.exists())
            store.abort_all()

            restarted = capture.CaptureStore(session, manifest_path)
            restarted._h_cache_fetch_started = True
            try:
                save(restarted, b_cache, b"B.Cache")
                save(restarted, h_cache, body)
                self.assertFalse(unmanaged.exists())
                self.assertEqual(restarted.manifest["conflict_count"], 1)
            finally:
                restarted.abort_all()

    def test_worker_restart_uses_previous_b_cache_for_later_h_cache(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp) / "session"
            session.mkdir()
            manifest_path = self.manifest_path_for(session)
            capture.initialize_session_manifest(session, nct_config.DEFAULT_CONFIG, manifest_path)
            store = capture.CaptureStore(session, manifest_path)
            store._h_cache_fetch_started = True
            writer = store.begin("https://content.warframe.com/0/B.Cache.Windows.bin!E_hash", 200, 1)
            writer.feed(b"B")
            writer.feed(b"")
            store.abort_all()
            restarted = capture.CaptureStore(session, manifest_path)
            try:
                body = make_shcc_container()
                writer = restarted.begin("https://content.warframe.com/0/H.Cache.bin!E_---------------------w", 200, len(body))
                writer.feed(body)
                writer.feed(b"")
                self.assertTrue((session / "OpenWF" / "Content" / "0" / "UNMANAGED").is_file())
                self.assertFalse(restarted.capture_disabled)
            finally:
                restarted.abort_all()

    def test_worker_restart_rejects_previously_invalidated_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp) / "session"
            session.mkdir()
            manifest_path = self.manifest_path_for(session)
            capture.initialize_session_manifest(session, nct_config.DEFAULT_CONFIG, manifest_path)
            manifest = common.read_json_object(manifest_path)
            manifest["update_transition_detected"] = True
            common.atomic_write_json(manifest_path, manifest)
            with self.assertRaisesRegex(RuntimeError, "multiple update states"):
                capture.CaptureStore(session, manifest_path)

    def test_direct_h_cache_type_mismatch_with_b_cache_stops_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp) / "session"
            session.mkdir()
            manifest_path = self.manifest_path_for(session)
            capture.initialize_session_manifest(session, nct_config.DEFAULT_CONFIG, manifest_path)
            store = capture.CaptureStore(session, manifest_path)
            h_cache = make_shcc_container(b"type-D")
            direct = store.begin(
                "https://content.warframe.com/0/H.Cache.bin!D_---------------------w",
                200,
                len(h_cache),
            )
            direct.feed(h_cache)
            direct.feed(b"")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                store.maybe_fetch_official_h_cache("/0/B.Cache.Windows.bin!E_hash")

            manifest = common.read_json_object(manifest_path)
            self.assertTrue(manifest["update_transition_detected"])
            self.assertTrue(store.capture_disabled)
            self.assertTrue(store.drain_requested.is_set())
            self.assertFalse((session / "OpenWF" / "Content" / "0" / "UNMANAGED").exists())
            self.assertIn("B.Cache manifest type changed during the same capture (D -> E)", output.getvalue())

    def test_session_start_clears_owned_stale_output_temp_before_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            temporary = common.prepare_capture_temp_root(root)
            stale = temporary / "stale.part"
            stale.write_bytes(b"partial")
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            session = nct.CaptureSession(options)
            stdout = io.StringIO()
            with (
                mock.patch.object(windows_proxy, "restore_stale_recovery", return_value=None),
                mock.patch.object(common, "prepare_runtime_state_directory"),
                mock.patch.object(common, "prepare_output_directory", return_value=2 * 1024 * 1024 * 1024),
                mock.patch.object(common, "recover_stale_sessions", return_value=(0, [])) as recover,
                mock.patch.object(nct_runtime, "ensure_mitmproxy_ca_trusted", return_value=False),
                mock.patch.object(session, "_start_worker"),
                mock.patch.object(session, "_wait_for_worker_ready"),
                contextlib.redirect_stdout(stdout),
            ):
                session.start()
            recover.assert_called_once_with(root)
            self.assertFalse(temporary.exists())
            self.assertIn("Removed stale temporary capture data from the previous session", stdout.getvalue())
            assert session.logger is not None
            session.logger.close()

    def test_session_start_silently_removes_marker_only_temp_from_normal_previous_close(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            temporary = common.prepare_capture_temp_root(root)
            (temporary / "downloads").mkdir()
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            session = nct.CaptureSession(options)
            stdout = io.StringIO()
            with (
                mock.patch.object(windows_proxy, "restore_stale_recovery", return_value=None),
                mock.patch.object(common, "prepare_runtime_state_directory"),
                mock.patch.object(common, "prepare_output_directory", return_value=2 * 1024 * 1024 * 1024),
                mock.patch.object(common, "recover_stale_sessions", return_value=(0, [])),
                mock.patch.object(nct_runtime, "ensure_mitmproxy_ca_trusted", return_value=False),
                mock.patch.object(session, "_start_worker"),
                mock.patch.object(session, "_wait_for_worker_ready"),
                contextlib.redirect_stdout(stdout),
            ):
                session.start()
            self.assertFalse(temporary.exists())
            self.assertNotIn("Removed stale temporary capture data from the previous session", stdout.getvalue())
            assert session.logger is not None
            session.logger.close()

    def test_session_start_refuses_unowned_output_temp_without_deleting_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            temporary = root / ".temp"
            temporary.mkdir()
            important = temporary / "important.txt"
            important.write_text("keep", encoding="utf-8")
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            session = nct.CaptureSession(options)
            with (
                mock.patch.object(windows_proxy, "restore_stale_recovery", return_value=None),
                mock.patch.object(common, "prepare_runtime_state_directory"),
                mock.patch.object(common, "prepare_output_directory", return_value=2 * 1024 * 1024 * 1024),
                mock.patch.object(common, "recover_stale_sessions") as recover,
            ):
                with self.assertRaisesRegex(RuntimeError, "not a Ninja Capture Tool workspace"):
                    session.start()
            recover.assert_not_called()
            self.assertEqual(important.read_text(encoding="utf-8"), "keep")

    def test_restart_prompt_is_ignored_for_an_empty_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session_root = root / "session"
            session_root.mkdir()
            manifest_path = root / "session_session.json"
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            capture.initialize_session_manifest(session_root, options, manifest_path)
            session = nct.CaptureSession(options)
            session.session_root = session_root
            session.manifest_path = manifest_path
            with mock.patch.object(session, "_prompt_write") as prompt:
                session._begin_restart_prompt()
            self.assertIsNone(session.restart_prompt_state)
            self.assertFalse(session.suppress_console_output)
            prompt.assert_not_called()

    def test_restart_hotkey_can_be_deferred_until_restart_completes(self) -> None:
        session = nct.CaptureSession(dict(nct_config.DEFAULT_CONFIG))
        session.worker_active_captures = 1
        msvcrt = SimpleNamespace(
            kbhit=mock.Mock(side_effect=[True, False, False]),
            getwch=mock.Mock(return_value="\x12"),
        )
        stdin = SimpleNamespace(isatty=lambda: True)
        output = io.StringIO()
        with (
            mock.patch.object(nct_session.sys, "platform", "win32"),
            mock.patch.object(nct_session.sys, "stdin", stdin),
            mock.patch.dict(sys.modules, {"msvcrt": msvcrt}),
            mock.patch.object(session, "_session_has_restartable_activity", return_value=True),
            contextlib.redirect_stdout(output),
        ):
            session._poll_restart_hotkey(defer_restart=True)
            self.assertTrue(session.restart_prompt_deferred)
            with mock.patch.object(session, "_begin_restart_prompt") as begin_prompt:
                session._poll_restart_hotkey()

        self.assertFalse(session.restart_prompt_deferred)
        begin_prompt.assert_called_once_with()
        self.assertEqual(
            output.getvalue(),
            "[Session] New session request queued until restart completes.\n",
        )

    def test_restart_target_rejects_current_session_and_temp_descendants(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_root = root / "old"
            old_root.mkdir()
            old_manifest = root / "old_session.json"
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            capture.initialize_session_manifest(old_root, options, old_manifest)
            session = nct.CaptureSession(options)
            session.session_root = old_root
            session.manifest_path = old_manifest
            session.temp_root = root / ".temp"

            with self.assertRaisesRegex(RuntimeError, "inside the current capture session"):
                session._prepare_rotation_target("old/nested")
            with self.assertRaisesRegex(RuntimeError, "inside the current capture temporary directory"):
                session._prepare_rotation_target(".temp/nested")
            self.assertFalse((old_root / "nested").exists())
            self.assertFalse((root / ".temp" / "nested").exists())

    def test_restart_target_manifest_is_pending_until_worker_rotates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_root = root / "old"
            old_root.mkdir()
            old_manifest = root / "old_session.json"
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            capture.initialize_session_manifest(old_root, options, old_manifest)
            session = nct.CaptureSession(options)
            session.session_root = old_root
            session.manifest_path = old_manifest
            session.temp_root = root / ".temp"
            pending = session._prepare_rotation_target("new")
            try:
                self.assertEqual(common.read_json_object(Path(pending["manifest_path"]))["status"], "pending_rotation")
            finally:
                session._discard_rotation_target(pending)

            with (
                mock.patch.object(capture, "initialize_session_manifest", side_effect=OSError("manifest unavailable")),
                mock.patch.object(nct.shutil, "rmtree", side_effect=OSError("directory busy")),
                self.assertRaisesRegex(RuntimeError, "manifest unavailable.*directory busy"),
            ):
                session._prepare_rotation_target("broken")
            nct.shutil.rmtree(root / "broken", ignore_errors=True)

    def test_discarded_preexisting_empty_rotation_target_preserves_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_root = root / "old"
            old_root.mkdir()
            target = root / "prepared"
            target.mkdir()
            old_manifest = root / "old_session.json"
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            capture.initialize_session_manifest(old_root, options, old_manifest)
            session = nct.CaptureSession(options)
            session.session_root = old_root
            session.manifest_path = old_manifest
            session.temp_root = root / ".temp"
            pending = session._prepare_rotation_target("prepared")
            self.assertFalse(bool(pending["session_directory_created_by_tool"]))
            self.assertTrue(session._discard_rotation_target(pending))
            self.assertTrue(target.is_dir())
            self.assertEqual(list(target.iterdir()), [])
            self.assertFalse(Path(pending["manifest_path"]).exists())

    def test_recorded_session_recovery_covers_external_current_and_pending_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            current_parent = root / "drive-a"
            pending_parent = root / "drive-b"
            previous_parent = root / "drive-c"
            current = current_parent / "current"
            pending = pending_parent / "pending"
            previous = previous_parent / "previous"
            current.mkdir(parents=True)
            pending.mkdir(parents=True)
            previous.mkdir(parents=True)
            options = dict(nct_config.DEFAULT_CONFIG, output_root=current_parent, output_path=None)
            _, current_manifest = common.session_artifact_paths(current_parent, "current-meta")
            _, pending_manifest = common.session_artifact_paths(pending_parent, "pending-meta")
            _, previous_manifest = common.session_artifact_paths(previous_parent, "previous-meta")
            capture.initialize_session_manifest(current, options, current_manifest, status="running")
            capture.initialize_session_manifest(pending, options, pending_manifest, status="pending_rotation")
            capture.initialize_session_manifest(previous, options, previous_manifest, status="running")
            current_temp = common.prepare_capture_temp_root(current_parent)
            pending_temp = common.prepare_capture_temp_root(pending_parent)
            previous_temp = common.prepare_capture_temp_root(previous_parent)

            session = nct.CaptureSession(options)
            session.session_root = current
            session.manifest_path = current_manifest
            session.capture_active_announced = True
            session.unresolved_session_recovery.append(session._session_recovery_entry(previous, previous_manifest))
            rotation = {"session_root": pending, "manifest_path": pending_manifest}
            session.pending_rotation = rotation
            session._write_session_recovery_record()
            self.assertEqual(len(common.read_json_object(nct_session._SESSION_RECOVERY_FILE)["sessions"]), 3)

            interrupted, removed, warnings = nct_session.recover_recorded_capture_sessions()
            self.assertEqual((interrupted, removed, warnings), (2, 1, []))
            self.assertEqual(common.read_json_object(current_manifest)["status"], "interrupted")
            self.assertEqual(common.read_json_object(previous_manifest)["status"], "interrupted")
            self.assertFalse(pending.exists())
            self.assertFalse(pending_manifest.exists())
            self.assertFalse(current_temp.exists())
            self.assertFalse(pending_temp.exists())
            self.assertFalse(previous_temp.exists())
            self.assertFalse(nct_session._SESSION_RECOVERY_FILE.exists())

    def test_recorded_session_recovery_silently_removes_empty_startup_pending(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session_root = root / "starting"
            session_root.mkdir()
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            log_path, manifest_path = common.session_artifact_paths(root, "starting")
            capture.initialize_session_manifest(session_root, options, manifest_path, status="starting")
            log_path.write_text("startup close timed out before finalization\n", encoding="utf-8")
            manifest = common.read_json_object(manifest_path)
            temp_root = common.prepare_capture_temp_root(root)
            record_path = root / ".session-recovery.json"
            common.atomic_write_json(
                record_path,
                {
                    "version": 1,
                    "sessions": [
                        {
                            "session": str(session_root.resolve()),
                            "manifest": str(manifest_path.resolve()),
                            "session_id": manifest["session_id"],
                            "startup_pending": True,
                        }
                    ],
                },
            )

            interrupted, removed, warnings = nct_session.recover_recorded_capture_sessions(record_path)

            self.assertEqual((interrupted, removed, warnings), (0, 0, []))
            self.assertFalse(session_root.exists())
            self.assertFalse(log_path.exists())
            self.assertFalse(manifest_path.exists())
            self.assertFalse(temp_root.exists())
            self.assertFalse(record_path.exists())

    def test_startup_pending_with_captured_payload_is_still_recovered_as_interrupted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session_root = root / "starting"
            session_root.mkdir()
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            _, manifest_path = common.session_artifact_paths(root, "starting")
            capture.initialize_session_manifest(session_root, options, manifest_path, status="starting")
            payload = session_root / "OpenWF" / "Content" / "captured.bin"
            payload.parent.mkdir(parents=True)
            payload.write_bytes(b"captured")
            manifest = common.read_json_object(manifest_path)
            manifest["captured_files"] = 1
            manifest["captured_bytes"] = len(b"captured")
            common.atomic_write_json(manifest_path, manifest)
            record_path = root / ".session-recovery.json"
            common.atomic_write_json(
                record_path,
                {
                    "version": 1,
                    "sessions": [
                        {
                            "session": str(session_root.resolve()),
                            "manifest": str(manifest_path.resolve()),
                            "session_id": manifest["session_id"],
                            "startup_pending": True,
                        }
                    ],
                },
            )

            interrupted, removed, warnings = nct_session.recover_recorded_capture_sessions(record_path)

            self.assertEqual((interrupted, removed, warnings), (1, 0, []))
            self.assertTrue(payload.exists())
            self.assertEqual(common.read_json_object(manifest_path)["status"], "interrupted")
            self.assertFalse(record_path.exists())

    def test_recorded_session_recovery_silently_removes_empty_aborted_startup_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session_root = root / "aborted"
            session_root.mkdir()
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            log_path, manifest_path = common.session_artifact_paths(root, "aborted")
            capture.initialize_session_manifest(session_root, options, manifest_path, status="aborted")
            log_path.write_text("startup was closed before capture became active\n", encoding="utf-8")
            manifest = common.read_json_object(manifest_path)
            record_path = root / ".session-recovery.json"
            common.atomic_write_json(
                record_path,
                {
                    "version": 1,
                    "sessions": [
                        {
                            "session": str(session_root.resolve()),
                            "manifest": str(manifest_path.resolve()),
                            "session_id": manifest["session_id"],
                        }
                    ],
                },
            )

            interrupted, removed, warnings = nct_session.recover_recorded_capture_sessions(record_path)

            self.assertEqual((interrupted, removed, warnings), (0, 0, []))
            self.assertFalse(session_root.exists())
            self.assertFalse(log_path.exists())
            self.assertFalse(manifest_path.exists())
            self.assertFalse(record_path.exists())

    def test_recorded_session_recovery_preserves_unresolved_or_malformed_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            record_path = root / ".session-recovery.json"
            entry = {
                "session": str((root / "external" / "session").resolve()),
                "manifest": str((root / "external" / "session_session.json").resolve()),
                "session_id": "1" * 32,
            }
            common.atomic_write_json(record_path, {"version": 1, "sessions": [entry]})
            with mock.patch.object(
                common,
                "validate_existing_session_root",
                side_effect=RuntimeError("drive is unavailable"),
            ):
                interrupted, removed, warnings = nct_session.recover_recorded_capture_sessions(record_path)
            self.assertEqual((interrupted, removed), (0, 0))
            self.assertTrue(any("retried on the next launch" in warning for warning in warnings))
            self.assertEqual(common.read_json_object(record_path)["sessions"], [entry])

            with mock.patch.object(
                common,
                "clear_stale_capture_temp",
                side_effect=RuntimeError("temporary data is still locked"),
            ):
                interrupted, removed, warnings = nct_session.recover_recorded_capture_sessions(record_path)
            self.assertEqual((interrupted, removed), (0, 0))
            self.assertTrue(record_path.exists())
            self.assertTrue(any("temporary data is still locked" in warning for warning in warnings))

            valid_session = root / "valid-pending"
            valid_session.mkdir()
            valid_manifest = root / "valid-pending_session.json"
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            capture.initialize_session_manifest(valid_session, options, valid_manifest, status="pending_rotation")
            malformed = {"session": "relative", "manifest": "relative"}
            valid_manifest_data = common.read_json_object(valid_manifest)
            valid_entry = {
                "session": str(valid_session.resolve()),
                "manifest": str(valid_manifest.resolve()),
                "session_id": valid_manifest_data["session_id"],
            }
            common.atomic_write_json(record_path, {"version": 1, "sessions": [malformed, valid_entry]})
            interrupted, removed, warnings = nct_session.recover_recorded_capture_sessions(record_path)
            self.assertEqual((interrupted, removed), (0, 1))
            self.assertFalse(valid_session.exists())
            self.assertFalse(valid_manifest.exists())
            self.assertFalse(record_path.exists())
            archived = list(root.glob(".session-recovery.json.invalid-*"))
            self.assertEqual(len(archived), 1)
            self.assertEqual(common.read_json_object(archived[0])["sessions"], [malformed])
            self.assertTrue(any("malformed session recovery entry" in warning for warning in warnings))

            record_path.write_text("{", encoding="utf-8")
            interrupted, removed, warnings = nct_session.recover_recorded_capture_sessions(record_path)
            self.assertEqual((interrupted, removed), (0, 0))
            self.assertFalse(record_path.exists())
            archived = list(root.glob(".session-recovery.json.invalid-*"))
            self.assertEqual(len(archived), 2)
            self.assertTrue(any("preserved at" in warning for warning in warnings))

    def test_recorded_session_recovery_rejects_entry_without_session_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = root / "session"
            session.mkdir()
            manifest_path = root / "session_session.json"
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            capture.initialize_session_manifest(session, options, manifest_path, status="running")
            record_path = root / ".session-recovery.json"
            entry = {
                "session": str(session.resolve()),
                "manifest": str(manifest_path.resolve()),
            }
            common.atomic_write_json(record_path, {"version": 1, "sessions": [entry]})

            interrupted, removed, warnings = nct_session.recover_recorded_capture_sessions(record_path)

            self.assertEqual((interrupted, removed), (0, 0))
            self.assertEqual(common.read_json_object(manifest_path)["status"], "running")
            self.assertTrue(session.exists())
            self.assertFalse(record_path.exists())
            archived = list(root.glob(".session-recovery.json.invalid-*"))
            self.assertEqual(len(archived), 1)
            self.assertEqual(common.read_json_object(archived[0])["sessions"], [entry])
            self.assertTrue(any("malformed session recovery entry" in warning for warning in warnings))

    def test_capture_manifest_without_session_id_is_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = root / "session"
            session.mkdir()
            manifest_path = root / "session_session.json"
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            capture.initialize_session_manifest(session, options, manifest_path, status="running")
            manifest = common.read_json_object(manifest_path)
            manifest.pop("session_id")
            common.atomic_write_json(manifest_path, manifest)

            self.assertIsNone(common.load_capture_session_manifest(manifest_path))

    def test_recorded_session_recovery_refuses_reused_path_with_different_session_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = root / "session"
            session.mkdir()
            manifest_path = root / "session_session.json"
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            capture.initialize_session_manifest(session, options, manifest_path, status="running")
            actual_id = common.read_json_object(manifest_path)["session_id"]
            self.assertNotEqual(actual_id, "0" * 32)
            record_path = root / ".session-recovery.json"
            entry = {
                "session": str(session.resolve()),
                "manifest": str(manifest_path.resolve()),
                "session_id": "0" * 32,
            }
            common.atomic_write_json(record_path, {"version": 1, "sessions": [entry]})

            interrupted, removed, warnings = nct_session.recover_recorded_capture_sessions(record_path)
            self.assertEqual((interrupted, removed), (0, 0))
            self.assertEqual(common.read_json_object(manifest_path)["status"], "running")
            self.assertTrue(session.exists())
            self.assertEqual(common.read_json_object(record_path)["sessions"], [entry])
            self.assertTrue(any("identity no longer matches" in warning for warning in warnings))

    def test_session_recovery_record_copies_immutable_session_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session_root = root / "session"
            session_root.mkdir()
            manifest_path = root / "session_session.json"
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            capture.initialize_session_manifest(session_root, options, manifest_path, status="running")
            manifest_id = common.read_json_object(manifest_path)["session_id"]
            session = nct.CaptureSession(options)
            entry = session._session_recovery_entry(session_root, manifest_path)
            self.assertEqual(entry["session_id"], manifest_id)

    def test_discard_rotation_target_never_deletes_a_promoted_running_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_parent = root / "old-parent"
            new_parent = root / "new-parent"
            old_session = old_parent / "old"
            new_session = new_parent / "new"
            old_session.mkdir(parents=True)
            new_session.mkdir(parents=True)
            options = dict(nct_config.DEFAULT_CONFIG, output_root=old_parent, output_path=None)
            _, old_manifest = common.session_artifact_paths(old_parent, "old-meta")
            new_log, new_manifest = common.session_artifact_paths(new_parent, "new-meta")
            capture.initialize_session_manifest(old_session, options, old_manifest, status="running")
            capture.initialize_session_manifest(new_session, options, new_manifest, status="running")
            payload = new_session / "OpenWF" / "Content" / "captured.bin"
            payload.parent.mkdir(parents=True)
            payload.write_bytes(b"keep")
            new_temp = common.prepare_capture_temp_root(new_parent)

            session = nct.CaptureSession(options)
            pending = {
                "session_root": new_session,
                "manifest_path": new_manifest,
                "log_path": new_log,
                "temp_root": new_temp,
                "old_temp_root": old_parent / ".temp",
            }
            self.assertFalse(session._discard_rotation_target(pending))
            self.assertEqual(payload.read_bytes(), b"keep")
            self.assertEqual(common.read_json_object(new_manifest)["status"], "running")
            self.assertTrue(new_temp.exists())

            self.assertTrue(session._discard_rotation_target(pending, worker_stopped=True))
            self.assertEqual(payload.read_bytes(), b"keep")
            recovered_manifest = common.read_json_object(new_manifest)
            self.assertEqual(recovered_manifest["status"], "interrupted")
            self.assertEqual(recovered_manifest["end_reason"], "interrupted")
            self.assertFalse(new_temp.exists())

    def test_session_directory_name_temp_is_reserved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for value in (".temp", "nested/.TEMP"):
                with self.subTest(value=value), self.assertRaisesRegex(ValueError, "reserved Ninja Capture Tool"):
                    common.resolve_session_output_path(value, root, "Session path")

    def test_pending_rotation_started_at_is_replaced_when_it_really_starts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session_root = root / "new"
            session_root.mkdir()
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            _, manifest_path = common.session_artifact_paths(root, "new-meta")
            capture.initialize_session_manifest(session_root, options, manifest_path, status="pending_rotation")
            manifest = common.read_json_object(manifest_path)
            manifest["started_at"] = "2000-01-01T00:00:00+00:00"
            common.atomic_write_json(manifest_path, manifest)
            store = capture.CaptureStore(session_root, manifest_path=manifest_path)
            try:
                with mock.patch.object(capture, "current_timestamp", return_value="2026-09-07T12:00:00+02:00"):
                    store.mark_running()
                updated = common.read_json_object(manifest_path)
                self.assertEqual(updated["status"], "running")
                self.assertEqual(updated["started_at"], "2026-09-07T12:00:00+02:00")
            finally:
                store.close_metadata()
                common.remove_capture_temp_root(store.temp_root)

    def test_restart_prompt_replays_all_permanent_worker_lines_after_console_suppression(self) -> None:
        session = nct.CaptureSession(dict(nct_config.DEFAULT_CONFIG))
        session.restart_prompt_state = "confirm"
        session.suppress_console_output = True
        output = io.StringIO()
        try:
            with contextlib.redirect_stdout(output):
                session._persist_and_queue_worker_output("[Saved] 1 B | 200 | /a.bin")
                session._persist_and_queue_worker_output("WARNING: capture warning", urgent=True)
                with session.worker_console_condition:
                    self.assertEqual(len(session.worker_console_queue), 1)
                    self.assertEqual(len(session.worker_console_urgent_queue), 1)
                self.assertEqual(output.getvalue(), "")
                session._close_restart_prompt()
                deadline = time.monotonic() + 1.0
                while "[Saved] 1 B | 200 | /a.bin" not in output.getvalue():
                    if time.monotonic() >= deadline:
                        break
                    time.sleep(0.01)
            self.assertIn("WARNING: capture warning", output.getvalue())
            self.assertIn("[Saved] 1 B | 200 | /a.bin", output.getvalue())
        finally:
            session._stop_worker_console_dispatcher()

    def test_custom_session_name_is_rejected_when_sidecar_already_refers_to_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            requested = root / "U43.5.1"
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            _, manifest_path = common.session_artifact_paths(root, "older-metadata-name")
            capture.initialize_session_manifest(requested, options, manifest_path, status="completed")
            manifest = common.read_json_object(manifest_path)
            manifest["finished_at"] = common.current_timestamp()
            common.atomic_write_json(manifest_path, manifest)
            with self.assertRaisesRegex(RuntimeError, "metadata already refers"):
                common.create_exact_session_directory(requested)
            self.assertFalse(requested.exists())

    def test_capture_addon_session_rotation_waits_for_active_writer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_session = root / "old"
            new_session = root / "new"
            old_session.mkdir()
            new_session.mkdir()
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            old_manifest = root / "old_session.json"
            new_manifest = root / "new_session.json"
            capture.initialize_session_manifest(old_session, options, old_manifest)
            capture.initialize_session_manifest(new_session, options, new_manifest)
            addon = capture.CaptureAddon(old_session, old_manifest, worker_protocol_enabled=True)
            rotated_lock_states: list[bool] = []

            def observe_worker_print(value: object, *args, **kwargs) -> None:
                try:
                    message = common.parse_worker_message(str(value))
                except ValueError:
                    message = None
                if message is not None and message.get("type") == "rotated":
                    acquired = addon._session_lock.acquire(blocking=False)
                    if acquired:
                        addon._session_lock.release()
                    rotated_lock_states.append(not acquired)

            with contextlib.redirect_stdout(io.StringIO()):
                addon.running()
                writer = addon.store.begin("https://content.warframe.com/file.bin", 200, 3)
                with mock.patch("builtins.print", side_effect=observe_worker_print):
                    addon.request_session_rotation(new_session, new_manifest, "token")
                    time.sleep(0.1)
                    self.assertEqual(addon.store.session_root, old_session.resolve())
                    writer.feed(b"abc")
                    writer.feed(b"")
                    thread = addon._rotation_thread
                    self.assertIsNotNone(thread)
                    thread.join(timeout=2.0)
                    self.assertFalse(thread.is_alive())
                    self.assertEqual(addon.store.session_root, new_session.resolve())
                    addon.done()
            self.assertEqual(rotated_lock_states, [True])

            cancel_old = root / "cancel-old"
            cancel_new = root / "cancel-new"
            cancel_old.mkdir()
            cancel_new.mkdir()
            cancel_old_manifest = root / "cancel-old_session.json"
            cancel_new_manifest = root / "cancel-new_session.json"
            capture.initialize_session_manifest(cancel_old, options, cancel_old_manifest)
            capture.initialize_session_manifest(cancel_new, options, cancel_new_manifest, status="pending_rotation")
            cancelling_addon = capture.CaptureAddon(cancel_old, cancel_old_manifest, worker_protocol_enabled=True)
            with contextlib.redirect_stdout(io.StringIO()):
                cancelling_addon.running()
                writer = cancelling_addon.store.begin("https://content.warframe.com/large.bin", 200, 1024)
                cancelling_addon.request_session_rotation(cancel_new, cancel_new_manifest, "cancel-token")
                time.sleep(0.1)
                thread = cancelling_addon._rotation_thread
                self.assertIsNotNone(thread)
                self.assertTrue(thread.is_alive())
                cancelling_addon.done()
                self.assertFalse(thread.is_alive())
                self.assertEqual(cancelling_addon.store.session_root, cancel_old.resolve())
                self.assertTrue(writer.failed)

    def test_session_rotation_refuses_cutover_when_old_manifest_cannot_flush(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_session = root / "old"
            new_session = root / "new"
            old_session.mkdir()
            new_session.mkdir()
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            old_manifest = root / "old_session.json"
            new_manifest = root / "new_session.json"
            capture.initialize_session_manifest(old_session, options, old_manifest)
            capture.initialize_session_manifest(new_session, options, new_manifest, status="pending_rotation")
            addon = capture.CaptureAddon(old_session, old_manifest, worker_protocol_enabled=True)
            output = io.StringIO()
            with (
                contextlib.redirect_stdout(output),
                mock.patch.object(addon.store, "flush_manifest", return_value=False),
            ):
                addon.running()
                addon.request_session_rotation(new_session, new_manifest, "token")
                thread = addon._rotation_thread
                self.assertIsNotNone(thread)
                thread.join(timeout=2.0)
                self.assertFalse(thread.is_alive())
                self.assertEqual(addon.store.session_root, old_session.resolve())
                addon.done()
            message = common.parse_worker_message(output.getvalue().splitlines()[-1])
            self.assertEqual(message["type"], "rotation_failed")
            self.assertIn("flush the current capture session metadata", str(message["error"]))

    def test_exact_output_path_rejects_symlink_session_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            target.mkdir()
            link = root / "session-link"
            try:
                link.symlink_to(target, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"Directory symlink creation is unavailable: {exc}")
            with self.assertRaisesRegex(RuntimeError, "symbolic link, junction, or reparse point"):
                common.create_exact_session_directory(link)
            with self.assertRaisesRegex(RuntimeError, "symbolic link, junction, or reparse point"):
                common.resolve_session_output_path(
                    link,
                    root,
                    "Session path",
                    reject_existing_reparse=True,
                )

    def test_initial_session_creation_rolls_back_if_manifest_initialization_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            requested = root / "nested" / "U43.5.4"
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=requested)
            session = nct.CaptureSession(options)
            with (
                mock.patch.object(windows_proxy, "restore_stale_recovery", return_value=None),
                mock.patch.object(common, "prepare_runtime_state_directory"),
                mock.patch.object(common, "prepare_output_directory", return_value=2 * 1024 * 1024 * 1024),
                mock.patch.object(common, "recover_stale_session", return_value=(0, [], True)),
                mock.patch.object(capture, "initialize_session_manifest", side_effect=OSError("manifest unavailable")),
            ):
                with self.assertRaisesRegex(OSError, "manifest unavailable"):
                    session.start()
            self.assertFalse(requested.exists())
            self.assertFalse(any(root.glob("*_session.json")))
            self.assertFalse(any(root.glob("*_capture.log")))

    def test_startup_rollback_preserves_preexisting_empty_exact_output_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            requested = root / "U43.5.4"
            requested.mkdir()
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=requested)
            session = nct.CaptureSession(options)
            with (
                mock.patch.object(windows_proxy, "restore_stale_recovery", return_value=None),
                mock.patch.object(common, "prepare_runtime_state_directory"),
                mock.patch.object(common, "prepare_output_directory", return_value=2 * 1024 * 1024 * 1024),
                mock.patch.object(common, "recover_stale_sessions"),
                mock.patch.object(capture, "initialize_session_manifest", side_effect=OSError("manifest unavailable")),
            ):
                with self.assertRaisesRegex(OSError, "manifest unavailable"):
                    session.start()
            self.assertTrue(requested.is_dir())
            self.assertEqual(list(requested.iterdir()), [])
            self.assertFalse(any(root.glob("*_session.json")))
            self.assertFalse(any(root.glob("*_capture.log")))

    def test_session_output_path_rejects_windows_invalid_components(self) -> None:
        for value in (
            "captures/bad?name",
            "captures/bad*name",
            "captures/CON",
            "captures/trailing.",
            "A:",
            "./captures",
            "captures/.",
            r"\Captures\U43.5.1",
            r"\\?\C:\Captures\U43.5.1",
            r"\\?\GLOBALROOT\Device\HarddiskVolume1\Captures",
            r"\\.\PhysicalDrive0",
            r"\??\C:\Captures\U43.5.1",
        ):
            with self.subTest(value=value), self.assertRaises((RuntimeError, ValueError)):
                common.resolve_session_output_path(value, Path.cwd(), "Session path")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertEqual(common.resolve_session_output_path("~", root, "Session path"), (root / "~").resolve())

    def test_existing_empty_exact_output_is_accepted_for_new_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            requested = root / "U43.5.4"
            requested.mkdir()
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=requested)
            session = nct.CaptureSession(options)
            with (
                mock.patch.object(windows_proxy, "restore_stale_recovery", return_value=None),
                mock.patch.object(common, "prepare_runtime_state_directory"),
                mock.patch.object(nct_runtime, "ensure_mitmproxy_ca_trusted", return_value=False),
                mock.patch.object(common, "prepare_output_directory", return_value=2 * 1024 * 1024 * 1024),
                mock.patch.object(common, "recover_stale_sessions") as recover,
                mock.patch.object(nct_session, "SessionLogger"),
                mock.patch.object(session, "_start_worker"),
                mock.patch.object(session, "_wait_for_worker_ready"),
            ):
                session.start()
            recover.assert_not_called()
            self.assertEqual(session.session_root, requested)
            self.assertFalse(session.session_directory_created_by_tool)
            assert session.manifest_path is not None
            manifest = common.read_json_object(session.manifest_path)
            self.assertEqual(manifest["capture_directory"], requested.name)
            self.assertFalse(manifest["session_directory_created_by_tool"])

    def test_clean_completed_session_without_captures_is_removed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            session = nct.CaptureSession(options)
            session.session_root = common.create_session_directory(root)
            session.log_path, session.manifest_path = common.session_artifact_paths(root, session.session_root.name)
            capture.initialize_session_manifest(session.session_root, options, session.manifest_path)
            session.logger = nct_session.SessionLogger(session.log_path)
            logger = session.logger
            session.started = True
            session_root = session.session_root
            log_path = session.log_path
            manifest_path = session.manifest_path
            original_unlink = Path.unlink

            def windows_style_unlink(path: Path, *args, **kwargs):
                if path == log_path and logger._file is not None:
                    raise PermissionError("simulated Windows sharing violation")
                return original_unlink(path, *args, **kwargs)

            with (
                contextlib.redirect_stdout(io.StringIO()),
                mock.patch.object(Path, "unlink", new=windows_style_unlink),
            ):
                session.cleanup()
            self.assertFalse(session_root.exists())
            self.assertFalse(log_path.exists())
            self.assertFalse(manifest_path.exists())

    def test_clean_empty_session_preserves_preexisting_exact_output_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            requested = root / "U43.5.4"
            requested.mkdir()
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=requested)
            session = nct.CaptureSession(options)
            session.session_root = requested
            session.session_directory_created_by_tool = False
            session.log_path, session.manifest_path = common.session_artifact_paths(root, "session-meta")
            capture.initialize_session_manifest(
                requested,
                options,
                session.manifest_path,
                session_directory_created_by_tool=False,
            )
            session.logger = nct_session.SessionLogger(session.log_path)
            session.started = True
            with contextlib.redirect_stdout(io.StringIO()):
                session.cleanup()
            self.assertTrue(requested.is_dir())
            self.assertEqual(list(requested.iterdir()), [])
            self.assertFalse(session.log_path.exists())
            self.assertFalse(session.manifest_path.exists())

    def test_failed_empty_session_is_preserved_for_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            session = nct.CaptureSession(options)
            session.session_root = common.create_session_directory(root)
            session.log_path, session.manifest_path = common.session_artifact_paths(root, session.session_root.name)
            capture.initialize_session_manifest(session.session_root, options, session.manifest_path)
            assert session.log_path is not None
            log_path = session.log_path
            session.logger = nct_session.SessionLogger(log_path)
            session.failed = True
            session.failure_reason = "proxy worker exited unexpectedly"
            session_root = session.session_root
            with contextlib.redirect_stdout(io.StringIO()):
                session.cleanup()
            self.assertTrue(session_root.exists())
            manifest = common.read_json_object(session.manifest_path)
            self.assertEqual(manifest["status"], "failed")
            self.assertEqual(manifest["failure_reason"], "proxy worker exited unexpectedly")
            log = log_path.read_text(encoding="utf-8")
            self.assertIn("[Failed] Capture ended.", log)
            self.assertIn("ERROR: proxy worker exited unexpectedly", log)

    def test_temp_cleanup_failure_is_recorded_as_session_warning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            session = nct.CaptureSession(options)
            session.session_root = common.create_session_directory(root)
            session.log_path, session.manifest_path = common.session_artifact_paths(root, session.session_root.name)
            capture.initialize_session_manifest(session.session_root, options, session.manifest_path)
            manifest = common.read_json_object(session.manifest_path)
            common.atomic_write_json(session.manifest_path, manifest)
            session.logger = nct_session.SessionLogger(session.log_path)
            session.started = True
            session.temp_root = common.prepare_capture_temp_root(root)
            temporary = session.temp_root
            with mock.patch.object(common, "remove_capture_temp_root", side_effect=OSError("locked")), contextlib.redirect_stdout(io.StringIO()):
                session.cleanup()
            manifest = common.read_json_object(session.manifest_path)
            self.assertEqual(manifest["cleanup_errors"], 1)
            self.assertEqual(manifest["status"], "completed_with_warnings")
            self.assertTrue(temporary.exists())
            self.assertFalse(nct_session._SESSION_RECOVERY_FILE.exists())
            self.assertIn(
                "WARNING: Could not remove temporary capture data: locked",
                session.log_path.read_text(encoding="utf-8"),
            )

    def test_cleanup_keeps_recovery_record_when_session_finalization_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            session = nct.CaptureSession(options)
            session.session_root = common.create_session_directory(root)
            session.log_path, session.manifest_path = common.session_artifact_paths(root, session.session_root.name)
            capture.initialize_session_manifest(session.session_root, options, session.manifest_path)
            session.logger = nct_session.SessionLogger(session.log_path)
            session.started = True
            session._write_session_recovery_record()
            with (
                mock.patch.object(capture, "finalize_session_manifest", side_effect=OSError("metadata locked")),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                session.cleanup()
            self.assertTrue(nct_session._SESSION_RECOVERY_FILE.exists())
            log = session.log_path.read_text(encoding="utf-8")
            self.assertIn("WARNING: Could not finalize session metadata: metadata locked", log)
            self.assertIn("[Recovery] Session recovery data was kept for the next launch", log)

    def test_cleanup_reports_recovery_file_cleanup_failure_without_claiming_proxy_restore_failed(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None)
        session = nct.CaptureSession(options)
        session.previous_proxy = {"before": True}
        session.applied_proxy = {"applied": True}
        output = io.StringIO()
        with (
            mock.patch.object(
                windows_proxy,
                "deactivate_local_proxy",
                return_value=windows_proxy.ProxyDeactivationResult(True, "recovery locked"),
            ),
            mock.patch.object(session, "_stop_worker", return_value=True),
            mock.patch.object(session, "_finalize_worker_state", return_value=True),
            mock.patch.object(session, "_write_session_recovery_record"),
            contextlib.redirect_stdout(output),
        ):
            session.cleanup()
        text = output.getvalue()
        self.assertIn("[Restored] Previous Windows proxy settings restored.", text)
        self.assertIn("proxy recovery record could not be removed: recovery locked", text)
        self.assertNotIn("ERROR: Could not restore previous Windows proxy settings", text)
        self.assertIsNone(session.previous_proxy)
        self.assertIsNone(session.applied_proxy)

    def test_capture_log_has_timestamps_without_changing_console_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "capture.log"
            logger = nct_session.SessionLogger(log_path)
            stdout = io.StringIO()
            with mock.patch.object(common, "current_timestamp", return_value="2026-08-31T12:34:56+02:00"), contextlib.redirect_stdout(stdout):
                logger.write("[Saved] 3 B | 200 | /a.bin")
            real_file = logger._file
            assert real_file is not None
            real_file.close()

            class FailingClose:
                def close(self) -> None:
                    raise OSError("final flush failed")

            logger._file = FailingClose()
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                logger.close()
            logger.write("late worker line", console=False)
            self.assertIn("Could not close capture log cleanly: final flush failed", stderr.getvalue())
            self.assertEqual(stdout.getvalue(), "[Saved] 3 B | 200 | /a.bin\n")
            self.assertEqual(
                log_path.read_text(encoding="utf-8"),
                "2026-08-31T12:34:56+02:00 [Saved] 3 B | 200 | /a.bin\n",
            )

    def test_capture_log_file_write_is_independent_of_blocked_console_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            logger = nct_session.SessionLogger(Path(tmp) / "capture.log")
            console_started = threading.Event()
            release_console = threading.Event()

            def blocked_print(*args, **kwargs) -> None:
                console_started.set()
                release_console.wait(2.0)

            with mock.patch.object(common, "print_console", side_effect=blocked_print):
                console_thread = threading.Thread(
                    target=logger.write,
                    args=("console line",),
                    kwargs={"file": False},
                )
                console_thread.start()
                self.assertTrue(console_started.wait(1.0))
                started = time.monotonic()
                logger.write("worker line", console=False)
                self.assertLess(time.monotonic() - started, 0.5)
                self.assertIn("worker line", (Path(tmp) / "capture.log").read_text(encoding="utf-8"))
                release_console.set()
                console_thread.join(timeout=1.0)
            logger.close()

    def test_live_saving_progress_is_console_only_and_cleared_by_permanent_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "capture.log"
            logger = nct_session.SessionLogger(log_path)
            stdout = io.StringIO()
            with (
                mock.patch.object(nct_session.SessionLogger, "_interactive_console", return_value=True),
                mock.patch.object(common, "console_supports_color", return_value=True),
                mock.patch.object(common, "current_timestamp", return_value="2026-09-03T09:34:56+02:00"),
                contextlib.redirect_stdout(stdout),
            ):
                logger.show_progress("[Saving] 2.5 MiB / 5.0 MiB (50.0%) | 2.0 MiB/s | /large.bin")
                logger.write("[Saved] 5.0 MiB | 200 | /large.bin")
            logger.close()
            rendered = stdout.getvalue()
            self.assertIn(
                "\r[Saving] \x1b[36m2.5 MiB / 5.0 MiB (50.0%)\x1b[0m | 2.0 MiB/s | /large.bin",
                rendered,
            )
            self.assertTrue(rendered.endswith("[Saved] 5.0 MiB | \x1b[32m200\x1b[0m | /large.bin\n"))
            self.assertEqual(
                log_path.read_text(encoding="utf-8"),
                "2026-09-03T09:34:56+02:00 [Saved] 5.0 MiB | 200 | /large.bin\n",
            )

    def test_live_saving_progress_is_suppressed_when_console_is_not_interactive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            logger = nct_session.SessionLogger(Path(tmp) / "capture.log")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                logger.show_progress("[Saving] 1.0 MiB | /unknown.bin")
            logger.close()
            self.assertEqual(stdout.getvalue(), "")

    def test_stale_recovery_preserves_failed_empty_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = root / "failed"
            session.mkdir()
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            log_path, manifest_path = self.make_sidecar_session_metadata(session, options)
            manifest = common.read_json_object(manifest_path)
            manifest["status"] = "failed"
            manifest["finished_at"] = common.current_timestamp()
            common.atomic_write_json(manifest_path, manifest)
            log_path.write_text("worker failed\n", encoding="utf-8")
            interrupted, warnings = common.recover_stale_sessions(root)
            self.assertEqual((interrupted, warnings), (0, []))
            self.assertTrue(session.exists())
            self.assertTrue(log_path.exists())
            self.assertEqual(common.read_json_object(manifest_path)["status"], "failed")

    def test_global_active_prompt_is_console_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            requested = root / "global-debug"
            options = dict(
                nct_config.DEFAULT_CONFIG,
                debug="global",
                output_root=root,
                output_path=requested,
            )
            session = nct.CaptureSession(options)
            stdout = io.StringIO()
            with (
                mock.patch.object(windows_proxy, "restore_stale_recovery", return_value=None),
                mock.patch.object(common, "prepare_runtime_state_directory"),
                mock.patch.object(nct_runtime, "ensure_mitmproxy_ca_trusted", return_value=False),
                mock.patch.object(common, "prepare_output_directory", return_value=2 * 1024 * 1024 * 1024),
                mock.patch.object(session, "_start_worker"),
                mock.patch.object(session, "_wait_for_worker_ready"),
                contextlib.redirect_stdout(stdout),
            ):
                session.start()

            active = "Capture is active. Start the Warframe Launcher or Warframe to capture downloaded assets."
            controls = "Press Ctrl+C when finished or Ctrl+R to start a new session."
            console = stdout.getvalue()
            self.assertEqual(console.count(active), 1)
            self.assertIn(active + "\n" + controls + "\n\n", console)
            self.assertNotIn(f"Ninja Capture Tool v{common.display_version()}", console)
            self.assertTrue(console.startswith("[Notice] Update Patch creation supports Warframe Hotfixes only;"))
            self.assertIn("~U43.5.1 / 4895911296145320793 -> U43.5.4, while U43.6 or U44 requires a newer base", console)
            self.assertLess(console.index("[Warframe] Checking live version..."), console.index("[Steam] Checking live manifest..."))
            self.assertLess(console.index("[Steam] Checking live manifest..."), console.index("Session: "))
            self.assertLess(console.index("Session: "), console.index("Mode: Local Capture"))
            self.assertLess(console.index("Mode: Local Capture"), console.index("Debug: Global"))
            self.assertNotIn("Processes:", console)
            self.assertNotIn("DNS types:", console)
            self.assertIn("Global debug can log hostnames and IP addresses", console)
            self.assertIn("review the session capture log before sharing it.", console)
            self.assertNotIn("timestamped capture log", console)
            self.assertNotIn("[Privacy]", console)

            assert session.log_path is not None
            log = session.log_path.read_text(encoding="utf-8")
            self.assertNotIn(active, log)
            self.assertNotIn("DNS types:", log)
            self.assertNotIn(f"Ninja Capture Tool v{common.display_version()}", log)
            self.assertNotIn("Session:", log)
            self.assertNotIn("Mode: Local Capture", log)
            self.assertNotIn("Processes: Launcher.exe, Warframe.x64.exe", log)
            self.assertNotIn("Debug: Global", log)
            self.assertNotIn("Global debug can log hostnames and IP addresses", log)
            assert session.manifest_path is not None
            manifest = common.read_json_object(session.manifest_path)
            self.assertEqual(manifest["application_version"], common.VERSION)
            self.assertEqual(manifest["capture_mode"], "local")
            self.assertEqual(manifest["processes"], ["Launcher.exe", "Warframe.x64.exe"])
            self.assertEqual(manifest["debug"], "global")
            self.assertIsInstance(manifest["started_at"], str)
            self.assertIsNone(manifest["finished_at"])
            assert session.logger is not None
            session.logger.close()

    def test_nonzero_worker_exit_during_console_close_is_not_a_failure(self) -> None:
        session = nct.CaptureSession(dict(nct_config.DEFAULT_CONFIG, output_root=Path("C:/output"), output_path=None))
        session.process = SimpleNamespace(poll=mock.Mock(return_value=1))
        session.request_console_shutdown()
        session.wait()
        self.assertFalse(session.failed)

    def test_stop_on_exit_waits_until_a_selected_process_has_been_seen(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, stop_on_exit=True, output_root=Path("C:/output"), output_path=None)
        session = nct.CaptureSession(options)
        session.process = SimpleNamespace(poll=mock.Mock(side_effect=[None, None, 0]), returncode=0)
        with (
            mock.patch.object(nct_runtime, "running_process_names", side_effect=[set(), set()]),
            mock.patch.object(nct.time, "sleep"),
            mock.patch.object(session, "log") as log,
        ):
            session.wait()
        self.assertFalse(any("Selected processes remained absent" in call.args[0] for call in log.call_args_list))

    def test_stop_on_exit_uses_singular_message_for_one_selected_process(self) -> None:
        options = dict(
            nct_config.DEFAULT_CONFIG,
            processes=["Launcher.exe"],
            stop_on_exit=True,
            stop_on_exit_delay=1,
            output_root=Path("C:/output"),
            output_path=None,
        )
        session = nct.CaptureSession(options)
        session.process = SimpleNamespace(poll=mock.Mock(return_value=None))
        with (
            mock.patch.object(nct_runtime, "running_process_names", side_effect=[{"launcher.exe"}, set(), set()]),
            mock.patch.object(nct.time, "monotonic", side_effect=[100.0, 101.0]),
            mock.patch.object(nct.time, "sleep"),
            mock.patch.object(session, "log") as log,
        ):
            session.wait()
        log.assert_called_once_with("[Stopping] Selected process remained absent for 1 second.")
        self.assertEqual(session.end_reason, "stop_on_exit")

    def test_stop_on_exit_grace_period_resets_when_a_selected_process_returns(self) -> None:
        options = dict(
            nct_config.DEFAULT_CONFIG,
            stop_on_exit=True,
            stop_on_exit_delay=15,
            output_root=Path("C:/output"),
            output_path=None,
        )
        session = nct.CaptureSession(options)
        session.process = SimpleNamespace(poll=mock.Mock(return_value=None))
        with (
            mock.patch.object(
                nct_runtime,
                "running_process_names",
                side_effect=[{"launcher.exe"}, set(), {"warframe.x64.exe"}, set(), set()],
            ),
            mock.patch.object(nct.time, "monotonic", side_effect=[100.0, 200.0, 215.0]),
            mock.patch.object(nct.time, "sleep"),
            mock.patch.object(session, "log") as log,
        ):
            session.wait()
        log.assert_called_once_with("[Stopping] Selected processes remained absent for 15 seconds.")

    def test_console_close_cleanup_suppresses_console_summary_but_keeps_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            session = nct.CaptureSession(options)
            session.session_root = common.create_session_directory(root)
            session.log_path, session.manifest_path = common.session_artifact_paths(root, session.session_root.name)
            capture.initialize_session_manifest(session.session_root, options, session.manifest_path)
            payload = session.session_root / "OpenWF" / "Content" / "a.bin"
            payload.parent.mkdir(parents=True)
            payload.write_bytes(b"x")
            manifest = common.read_json_object(session.manifest_path)
            manifest["captured_files"] = 1
            manifest["captured_bytes"] = 1
            common.atomic_write_json(session.manifest_path, manifest)
            assert session.log_path is not None
            log_path = session.log_path
            session.logger = nct_session.SessionLogger(log_path)
            session.started = True
            stdout = io.StringIO()
            session.request_console_shutdown()
            with contextlib.redirect_stdout(stdout):
                session.cleanup()
            self.assertEqual(stdout.getvalue(), "")
            self.assertFalse(session.failed)
            self.assertTrue(session.session_root.exists())
            log = log_path.read_text(encoding="utf-8")
            self.assertIn("Files: 1", log)

    def test_console_close_removes_temp_workspace_for_nonempty_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            session = nct.CaptureSession(options)
            session.session_root = common.create_session_directory(root)
            session.log_path, session.manifest_path = common.session_artifact_paths(root, session.session_root.name)
            capture.initialize_session_manifest(session.session_root, options, session.manifest_path)
            payload = session.session_root / "OpenWF" / "Content" / "a.bin"
            payload.parent.mkdir(parents=True)
            payload.write_bytes(b"x")
            manifest = common.read_json_object(session.manifest_path)
            manifest["captured_files"] = 1
            manifest["captured_bytes"] = 1
            common.atomic_write_json(session.manifest_path, manifest)
            session.temp_root = common.prepare_capture_temp_root(root)
            (session.temp_root / "unfinished.part").write_bytes(b"temporary")
            temp_root = session.temp_root
            assert session.log_path is not None
            session.logger = nct_session.SessionLogger(session.log_path)
            session.started = True
            session.request_console_shutdown()

            with (
                mock.patch.object(session, "_stop_worker", return_value=True),
                mock.patch.object(session, "_finalize_worker_state", return_value=True),
            ):
                session.cleanup()

            self.assertFalse(temp_root.exists())
            self.assertTrue(session.session_root.exists())

    def test_console_close_removes_clean_empty_session_and_temp_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            session = nct.CaptureSession(options)
            session.session_root = common.create_session_directory(root)
            session.log_path, session.manifest_path = common.session_artifact_paths(
                root, session.session_root.name
            )
            capture.initialize_session_manifest(session.session_root, options, session.manifest_path)
            session.temp_root = common.prepare_capture_temp_root(root)
            assert session.log_path is not None and session.manifest_path is not None
            session_root = session.session_root
            temp_root = session.temp_root
            log_path = session.log_path
            manifest_path = session.manifest_path
            session.logger = nct_session.SessionLogger(log_path)
            session.started = True
            session.request_console_shutdown()
            with (
                mock.patch.object(session, "_stop_worker", return_value=True),
                mock.patch.object(session, "_finalize_worker_state", return_value=True),
            ):
                session.cleanup()

            self.assertFalse(temp_root.exists())
            self.assertFalse(session_root.exists())
            self.assertFalse(log_path.exists())
            self.assertFalse(manifest_path.exists())

    def test_console_close_removes_filtered_only_session_and_temp_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            session = nct.CaptureSession(options)
            session.session_root = common.create_session_directory(root)
            session.log_path, session.manifest_path = common.session_artifact_paths(
                root, session.session_root.name
            )
            capture.initialize_session_manifest(session.session_root, options, session.manifest_path)
            manifest = common.read_json_object(session.manifest_path)
            manifest["filtered_root_paths"] = 3
            common.atomic_write_json(session.manifest_path, manifest)
            session.temp_root = common.prepare_capture_temp_root(root)
            assert session.log_path is not None and session.manifest_path is not None
            session_root = session.session_root
            temp_root = session.temp_root
            log_path = session.log_path
            manifest_path = session.manifest_path
            session.logger = nct_session.SessionLogger(log_path)
            session.started = True
            session.request_console_shutdown()
            with (
                mock.patch.object(session, "_stop_worker", return_value=True),
                mock.patch.object(session, "_finalize_worker_state", return_value=True),
            ):
                session.cleanup()

            self.assertFalse(temp_root.exists())
            self.assertFalse(session_root.exists())
            self.assertFalse(log_path.exists())
            self.assertFalse(manifest_path.exists())

    def test_console_close_preserves_preexisting_empty_exact_output_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            requested = root / "U43.5.4"
            requested.mkdir()
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=requested)
            session = nct.CaptureSession(options)
            session.session_root = requested
            session.session_directory_created_by_tool = False
            session.log_path, session.manifest_path = common.session_artifact_paths(root, "session-meta")
            capture.initialize_session_manifest(
                requested,
                options,
                session.manifest_path,
                session_directory_created_by_tool=False,
            )
            session.temp_root = common.prepare_capture_temp_root(root)
            assert session.log_path is not None and session.manifest_path is not None
            temp_root = session.temp_root
            log_path = session.log_path
            manifest_path = session.manifest_path
            session.logger = nct_session.SessionLogger(log_path)
            session.started = True
            session.request_console_shutdown()
            with (
                mock.patch.object(session, "_stop_worker", return_value=True),
                mock.patch.object(session, "_finalize_worker_state", return_value=True),
            ):
                session.cleanup()

            self.assertFalse(temp_root.exists())
            self.assertTrue(requested.is_dir())
            self.assertEqual(list(requested.iterdir()), [])
            self.assertFalse(log_path.exists())
            self.assertFalse(manifest_path.exists())

    def test_session_duration_uses_release_duration_format(self) -> None:
        manifest = {
            "started_at": "2026-09-23T10:00:00+02:00",
            "finished_at": "2026-09-23T10:01:05+02:00",
        }
        self.assertEqual(nct.CaptureSession._session_duration(manifest), "01:05")
        manifest["finished_at"] = "2026-09-23T11:01:01+02:00"
        self.assertEqual(nct.CaptureSession._session_duration(manifest), "01:01:01")

    def test_final_summary_is_hidden_only_for_nct_created_console(self) -> None:
        for console_created, expect_console in ((True, False), (False, True)):
            with self.subTest(console_created=console_created), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
                session = nct.CaptureSession(options)
                session.session_root = common.create_session_directory(root)
                session.log_path, session.manifest_path = common.session_artifact_paths(
                    root, session.session_root.name
                )
                capture.initialize_session_manifest(session.session_root, options, session.manifest_path)
                payload = session.session_root / "OpenWF" / "Content" / "a.bin"
                payload.parent.mkdir(parents=True)
                payload.write_bytes(b"x")
                manifest = common.read_json_object(session.manifest_path)
                manifest["captured_files"] = 1
                manifest["captured_bytes"] = 1
                common.atomic_write_json(session.manifest_path, manifest)
                assert session.log_path is not None
                log_path = session.log_path
                session.logger = nct_session.SessionLogger(log_path)
                session.started = True
                stdout = io.StringIO()
                with (
                    mock.patch.object(nct_runtime, "_CONSOLE_CREATED_BY_NCT", console_created),
                    contextlib.redirect_stdout(stdout),
                ):
                    remove_session, finalized = session._finish_manifest_and_summary()
                    self.assertFalse(remove_session)
                    self.assertTrue(finalized)
                session.logger.close()
                if expect_console:
                    self.assertIn("Files: 1", stdout.getvalue())
                else:
                    self.assertEqual(stdout.getvalue(), "")
                log = log_path.read_text(encoding="utf-8")
                self.assertIn("Files: 1", log)
                self.assertIn("Duration: 00:00", log)
                self.assertLess(log.index("Files: 1"), log.index("Duration: 00:00"))
                self.assertLess(log.index("Duration: 00:00"), log.index("Size: 1 B"))

    def test_console_title_includes_capture_mode_and_version_and_restores_original(self) -> None:
        calls: list[str] = []

        class Function:
            def __init__(self, callback):
                self.callback = callback
                self.argtypes = None
                self.restype = None

            def __call__(self, *args):
                return self.callback(*args)

        class Kernel32:
            def __init__(self):
                self.GetConsoleWindow = Function(lambda: 1)
                self.GetConsoleTitleW = Function(self.get_console_title)
                self.SetConsoleTitleW = Function(self.set_console_title)

            @staticmethod
            def get_console_title(buffer, size):
                buffer.value = "Original Title"
                return len(buffer.value)

            @staticmethod
            def set_console_title(title):
                calls.append(title)
                return 1

        with (
            mock.patch.object(nct.sys, "platform", "win32"),
            mock.patch.object(nct.ctypes, "WinDLL", return_value=Kernel32(), create=True),
            mock.patch.object(nct.atexit, "register"),
            mock.patch.object(nct_runtime, "_CONSOLE_TITLE_ORIGINAL", None),
            mock.patch.object(nct_runtime, "_CONSOLE_TITLE_SET", False),
        ):
            nct_runtime.set_console_title("local")
            nct_runtime.set_console_title("system-proxy")
            nct_runtime._restore_console_title()
        self.assertEqual(calls[0], f"Local Capture - Ninja Capture Tool (v{common.display_version()})")
        self.assertEqual(calls[1], f"System Proxy - Ninja Capture Tool (v{common.display_version()})")
        self.assertEqual(calls[-1], "Original Title")

    def test_suspend_console_quick_edit_restores_original_mode_after_startup_scope(self) -> None:
        original_mode = 0x00E7
        calls: list[tuple[int, int]] = []

        class Function:
            def __init__(self, callback):
                self.callback = callback
                self.argtypes = None
                self.restype = None

            def __call__(self, *args):
                return self.callback(*args)

        class Kernel32:
            def __init__(self):
                self.GetStdHandle = Function(lambda identifier: 123)
                self.GetConsoleMode = Function(self.get_console_mode)
                self.SetConsoleMode = Function(self.set_console_mode)

            @staticmethod
            def get_console_mode(handle, mode):
                mode._obj.value = original_mode
                return 1

            @staticmethod
            def set_console_mode(handle, mode):
                value = int(getattr(mode, "value", mode))
                calls.append((int(getattr(handle, "value", handle)), value))
                return 1

        with (
            mock.patch.object(nct.sys, "platform", "win32"),
            mock.patch.object(nct.ctypes, "WinDLL", return_value=Kernel32(), create=True),
        ):
            with self.assertRaisesRegex(RuntimeError, "startup failed"):
                with nct_runtime.suspend_console_quick_edit():
                    self.assertEqual(calls, [(123, original_mode & ~0x0040)])
                    raise RuntimeError("startup failed")

        self.assertEqual(calls, [(123, original_mode & ~0x0040), (123, original_mode)])

    def test_show_console_window_marks_only_allocated_console_as_nct_created(self) -> None:
        with (
            mock.patch.object(nct.sys, "platform", "win32"),
            mock.patch.object(nct.sys, "frozen", True, create=True),
            mock.patch.dict(nct.os.environ, {"NCT_HEADLESS": "1"}, clear=False),
            mock.patch.object(nct_runtime, "set_console_title") as set_title,
            mock.patch.object(nct_runtime, "restore_redirected_standard_streams") as restore_streams,
        ):
            nct_runtime.show_console_window()
        set_title.assert_not_called()
        restore_streams.assert_not_called()

        kernel32 = SimpleNamespace(
            GetConsoleWindow=mock.MagicMock(side_effect=[0, 1]),
            AttachConsole=mock.MagicMock(return_value=False),
            AllocConsole=mock.MagicMock(return_value=True),
        )
        user32 = SimpleNamespace(ShowWindow=mock.MagicMock(return_value=True))
        with (
            mock.patch.object(nct.sys, "platform", "win32"),
            mock.patch.object(nct.sys, "frozen", True, create=True),
            mock.patch.object(nct_runtime, "restore_redirected_standard_streams", return_value=False),
            mock.patch.object(nct_runtime, "set_console_title"),
            mock.patch.object(nct.ctypes, "WinDLL", side_effect=[kernel32, user32], create=True),
            mock.patch.object(nct_runtime, "_CONSOLE_CREATED_BY_NCT", False),
        ):
            nct_runtime.show_console_window()
            self.assertTrue(nct_runtime._CONSOLE_CREATED_BY_NCT)
        kernel32.AttachConsole.assert_called_once_with(0xFFFFFFFF)
        kernel32.AllocConsole.assert_called_once_with()

    def test_pre_active_console_close_recovers_without_any_shutdown_write(self) -> None:
        class ProcessEnded(BaseException):
            pass

        for phase in ("before_worker", "worker_ready"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                session = nct.CaptureSession(dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None))
                recovery = root / ".session-recovery.json"
                installed = {}

                class FakeKernel32:
                    def SetConsoleCtrlHandler(self, callback, add):
                        installed["close"] = callback
                        return True

                def interrupted_startup(*args):
                    if phase == "worker_ready":
                        manifest = common.read_json_object(session.manifest_path)
                        manifest["status"] = "running"
                        common.atomic_write_json(session.manifest_path, manifest)
                    before_close = recovery.read_bytes()
                    # The main thread never gets to cleanup. The callback returns
                    # after its wait, modelling Windows ending the stalled process.
                    with mock.patch.object(session.shutdown_complete, "wait", return_value=False), mock.patch.object(
                        common, "atomic_write_json", side_effect=AssertionError("close must not need a disk write")
                    ):
                        self.assertTrue(installed["close"](2))
                    self.assertEqual(recovery.read_bytes(), before_close)
                    raise ProcessEnded()

                with (
                    mock.patch.object(nct_session, "_SESSION_RECOVERY_FILE", recovery),
                    mock.patch.object(nct.sys, "platform", "win32"),
                    mock.patch.object(nct.signal, "signal"),
                    mock.patch.object(nct.ctypes, "WINFUNCTYPE", lambda *args: lambda callback: callback, create=True),
                    mock.patch.object(nct.ctypes, "windll", SimpleNamespace(kernel32=FakeKernel32()), create=True),
                    mock.patch.object(windows_proxy, "restore_stale_recovery", return_value=None),
                    mock.patch.object(common, "prepare_runtime_state_directory"),
                    mock.patch.object(common, "prepare_output_directory", return_value=2 * 1024**3),
                    mock.patch.object(nct_runtime, "ensure_mitmproxy_ca_trusted", side_effect=interrupted_startup if phase == "before_worker" else None, return_value=False),
                    mock.patch.object(session, "_start_worker"),
                    mock.patch.object(session, "_wait_for_worker_ready", side_effect=interrupted_startup if phase == "worker_ready" else None),
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    nct.install_termination_handlers(session)
                    try:
                        with self.assertRaises(ProcessEnded):
                            session.start()
                    finally:
                        if session.logger is not None:
                            session.logger.close()
                    self.assertFalse(session.capture_active_announced)
                    self.assertFalse(session.cleaned_up)
                    entry = common.read_json_object(recovery)["sessions"][0]
                    self.assertIs(entry.get("startup_pending"), True)
                    self.assertEqual(nct_session.recover_recorded_capture_sessions(recovery), (0, 0, []))
                    self.assertFalse(session.session_root.exists())
                    self.assertFalse(session.manifest_path.exists())
                    self.assertFalse(session.log_path.exists())
                    self.assertFalse(recovery.exists())

    def test_pending_startup_recovers_before_recovery_record_was_written(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = root / "unfinished-startup"
            session.mkdir()
            manifest = self.manifest_path_for(session)
            capture.initialize_session_manifest(session, nct_config.DEFAULT_CONFIG, manifest, cleanup_empty_startup=True)
            self.assertEqual(common.recover_stale_sessions(root), (0, []))
            self.assertFalse(session.exists())
            self.assertFalse(manifest.exists())

    def test_pending_startup_recovery_preserves_data_errors_and_active_sessions(self) -> None:
        for case in ("payload", "unrecorded_payload", "warning", "failed", "transition", "active", "legacy"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                session = root / "startup"
                session.mkdir()
                manifest_path = self.manifest_path_for(session)
                capture.initialize_session_manifest(session, nct_config.DEFAULT_CONFIG, manifest_path, status="running", cleanup_empty_startup=True)
                manifest = common.read_json_object(manifest_path)
                payload = session / "captured.bin"
                if case in {"payload", "unrecorded_payload"}:
                    payload.write_bytes(b"preserve")
                    if case == "payload":
                        manifest["captured_files"] = 1
                elif case == "warning":
                    manifest["capture_errors"] = 1
                elif case == "failed":
                    manifest["status"] = "failed"
                    manifest["failure_reason"] = "startup failed"
                elif case == "transition":
                    manifest["update_transition_detected"] = True
                common.atomic_write_json(manifest_path, manifest)
                entry = {"session": str(session), "manifest": str(manifest_path), "session_id": manifest["session_id"]}
                if case != "legacy":
                    entry["startup_pending"] = case != "active"
                recovery = root / ".session-recovery.json"
                common.atomic_write_json(recovery, {"version": 1, "sessions": [entry]})
                interrupted, removed, warnings = nct_session.recover_recorded_capture_sessions(recovery)
                self.assertEqual(removed, 0)
                self.assertEqual(warnings, [])
                self.assertEqual(interrupted, 0 if case == "failed" else 1)
                self.assertTrue(session.exists())
                self.assertTrue(manifest_path.exists())
                if case in {"payload", "unrecorded_payload"}:
                    self.assertEqual(payload.read_bytes(), b"preserve")

    def test_startup_pending_record_is_cleared_only_after_active_message(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = nct.CaptureSession(dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None))
            recovery = root / ".session-recovery.json"
            observed_pending = []

            def console(message):
                if "Capture is active" in message:
                    observed_pending.append(common.read_json_object(recovery)["sessions"][0]["startup_pending"])

            with (
                mock.patch.object(nct_session, "_SESSION_RECOVERY_FILE", recovery),
                mock.patch.object(windows_proxy, "restore_stale_recovery", return_value=None),
                mock.patch.object(common, "prepare_runtime_state_directory"),
                mock.patch.object(common, "prepare_output_directory", return_value=2 * 1024**3),
                mock.patch.object(nct_runtime, "ensure_mitmproxy_ca_trusted", return_value=False),
                mock.patch.object(session, "_start_worker"),
                mock.patch.object(session, "_wait_for_worker_ready"),
                mock.patch.object(session, "console", side_effect=console),
            ):
                try:
                    session.start()
                    self.assertEqual(observed_pending, [True])
                    self.assertIs(common.read_json_object(recovery)["sessions"][0]["startup_pending"], False)
                finally:
                    session.cleanup()

    def test_console_close_before_active_message_keeps_startup_pending(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            session = nct.CaptureSession(options)
            session.session_root = common.create_session_directory(root)
            _, session.manifest_path = common.session_artifact_paths(root, session.session_root.name)
            capture.initialize_session_manifest(session.session_root, options, session.manifest_path)
            recovery_path = root / ".session-recovery.json"
            session.request_console_shutdown()
            with mock.patch.object(nct_session, "_SESSION_RECOVERY_FILE", recovery_path):
                session._write_session_recovery_record(include_current=True)

            entry = common.read_json_object(recovery_path)["sessions"][0]
            self.assertIs(entry.get("startup_pending"), True)

            session.started = True
            session.capture_active_announced = False
            with mock.patch.object(nct_session, "_SESSION_RECOVERY_FILE", recovery_path):
                session._write_session_recovery_record(include_current=True)
            entry = common.read_json_object(recovery_path)["sessions"][0]
            self.assertIs(entry.get("startup_pending"), True)

    def test_console_close_request_uses_fast_worker_shutdown_on_main_cleanup(self) -> None:
        session = nct.CaptureSession(dict(nct_config.DEFAULT_CONFIG, output_root=Path("C:/output"), output_path=None))
        session.request_console_shutdown()
        self.assertEqual(session.end_reason, "console_close")
        with (
            mock.patch.object(session, "_stop_worker") as stop_worker,
            mock.patch.object(session, "_finalize_worker_state") as finalize_worker,
        ):
            session.cleanup()
        stop_worker.assert_called_once_with(fast=True)
        finalize_worker.assert_called_once_with(timeout=0.25)
        self.assertTrue(session.shutdown_complete.is_set())

    def test_ctrl_c_console_event_requests_normal_cleanup_instead_of_default_exit(self) -> None:
        session = nct.CaptureSession(dict(nct_config.DEFAULT_CONFIG, output_root=Path("C:/output"), output_path=None))
        installed = {}

        class FakeKernel32:
            def SetConsoleCtrlHandler(self, callback, add):
                installed["callback"] = callback
                installed["add"] = add
                return True

        def fake_winfunctype(*args, **kwargs):
            return lambda function: function

        with (
            mock.patch.object(nct.sys, "platform", "win32"),
            mock.patch.object(nct.ctypes, "WINFUNCTYPE", fake_winfunctype, create=True),
            mock.patch.object(nct.ctypes, "windll", SimpleNamespace(kernel32=FakeKernel32()), create=True),
        ):
            nct.install_termination_handlers(session)

        callback = installed["callback"]
        self.assertTrue(callback(0))
        self.assertTrue(session.shutdown_requested.is_set())
        self.assertEqual(session.end_reason, "ctrl_c")
        self.assertFalse(session.console_closing)
        self.assertTrue(installed["add"])

    def test_fast_worker_shutdown_falls_back_to_job_and_process_tree_after_grace_period(self) -> None:
        session = nct.CaptureSession(dict(nct_config.DEFAULT_CONFIG, output_root=Path("C:/output"), output_path=None))
        process = mock.Mock()
        process.poll.return_value = None
        process.wait.side_effect = [
            subprocess.TimeoutExpired("worker", 0.2),
            subprocess.TimeoutExpired("worker", 0.2),
            0,
        ]
        session.process = process
        session.worker_job = "job"
        with (
            mock.patch.object(nct.sys, "platform", "win32"),
            mock.patch.object(nct_runtime, "close_worker_job") as close_job,
            mock.patch.object(nct_runtime, "terminate_process_tree", return_value=True) as taskkill,
        ):
            session._stop_worker(fast=True)
        process.stdin.write.assert_called_once_with(common.encode_worker_message("shutdown") + "\n")
        process.stdin.flush.assert_called_once_with()
        self.assertEqual(close_job.call_args_list[0], mock.call("job"))
        self.assertEqual(
            process.wait.call_args_list,
            [mock.call(timeout=0.2), mock.call(timeout=0.2), mock.call(timeout=0.2)],
        )
        taskkill.assert_called_once_with(process, timeout=0.3)
        process.kill.assert_not_called()
        self.assertIsNone(session.worker_job)

    def test_fast_worker_shutdown_returns_when_control_command_ends_worker(self) -> None:
        session = nct.CaptureSession(dict(nct_config.DEFAULT_CONFIG, output_root=Path("C:/output"), output_path=None))
        process = mock.Mock()
        process.poll.return_value = None
        process.wait.return_value = 0
        session.process = process
        session.worker_job = "job"
        with (
            mock.patch.object(nct.sys, "platform", "win32"),
            mock.patch.object(nct_runtime, "close_worker_job") as close_job,
            mock.patch.object(nct_runtime, "terminate_process_tree") as taskkill,
        ):
            session._stop_worker(fast=True)
        process.stdin.write.assert_called_once_with(common.encode_worker_message("shutdown") + "\n")
        process.stdin.flush.assert_called_once_with()
        process.wait.assert_called_once_with(timeout=0.2)
        taskkill.assert_not_called()
        process.kill.assert_not_called()
        close_job.assert_called_once_with("job")
        self.assertIsNone(session.worker_job)

    def test_worker_shutdown_failure_keeps_live_process_attached(self) -> None:
        session = nct.CaptureSession(dict(nct_config.DEFAULT_CONFIG, output_root=Path("C:/output"), output_path=None))
        process = mock.Mock()
        process.poll.return_value = None
        process.wait.side_effect = subprocess.TimeoutExpired("worker", 0.2)
        session.process = process
        session.worker_job = "job"
        with (
            mock.patch.object(nct.sys, "platform", "win32"),
            mock.patch.object(nct_runtime, "close_worker_job"),
            mock.patch.object(nct_runtime, "terminate_process_tree", return_value=False),
        ):
            self.assertFalse(session._stop_worker(fast=True))
        self.assertIs(session.process, process)
        self.assertFalse(session._finalize_worker_state(timeout=0))
        self.assertIs(session.process, process)
        process.kill.assert_called_once_with()

    def test_cleanup_retries_when_fast_worker_shutdown_is_not_confirmed(self) -> None:
        session = nct.CaptureSession(dict(nct_config.DEFAULT_CONFIG, output_root=Path("C:/output"), output_path=None))
        session.session_root = Path("C:/output/session")
        session.temp_root = Path("C:/output/.temp")
        session.request_console_shutdown()
        finalized_manifest = {
            "status": "completed",
            "captured_files": 0,
            "captured_bytes": 0,
            "duplicates": 0,
            "conflict_count": 0,
            "filtered_root_paths": 0,
            "skipped_partial": 0,
            "skipped_http": 0,
            "incomplete_responses": 0,
            "capture_errors": 0,
            "extraction_errors": 0,
            "cleanup_errors": 0,
        }
        with (
            mock.patch.object(session, "_stop_worker", side_effect=[False, True]) as stop_worker,
            mock.patch.object(session, "_finalize_worker_state", return_value=True) as finalize_worker,
            mock.patch.object(session, "_write_session_recovery_record") as write_recovery,
            mock.patch.object(session, "_finalize_session_metadata", return_value=finalized_manifest) as finalize_metadata,
            mock.patch.object(session, "_finish_manifest_and_summary", return_value=(False, True)) as finish_manifest,
            mock.patch.object(session, "_stop_worker_console_dispatcher") as stop_dispatcher,
            mock.patch.object(common, "remove_capture_temp_root") as remove_temp,
        ):
            session.cleanup()
            self.assertFalse(session.cleaned_up)
            self.assertFalse(session.shutdown_complete.is_set())
            finalize_worker.assert_not_called()
            finalize_metadata.assert_not_called()
            remove_temp.assert_not_called()
            finish_manifest.assert_not_called()
            stop_dispatcher.assert_not_called()
            write_recovery.assert_called_once_with(include_current=True)

            session.cleanup()

        self.assertTrue(session.cleaned_up)
        self.assertTrue(session.shutdown_complete.is_set())
        self.assertEqual(stop_worker.call_args_list, [mock.call(fast=True), mock.call(fast=True)])
        finalize_worker.assert_called_once_with(timeout=0.25)
        finalize_metadata.assert_called_once_with()
        remove_temp.assert_called_once_with(session.temp_root)
        finish_manifest.assert_called_once_with(finalized_manifest, check_payload=True)
        stop_dispatcher.assert_called_once_with(timeout=0.25)

    def test_finalize_worker_state_detaches_only_after_process_exit(self) -> None:
        session = nct.CaptureSession(dict(nct_config.DEFAULT_CONFIG, output_root=Path("C:/output"), output_path=None))
        process = mock.Mock()
        process.poll.side_effect = [None, 0]
        process.stdin = mock.Mock()
        process.stdout = mock.Mock()
        reader = mock.Mock()
        reader.is_alive.return_value = False
        session.process = process
        session.reader_thread = reader
        self.assertFalse(session._finalize_worker_state(timeout=0))
        self.assertIs(session.process, process)
        self.assertTrue(session._finalize_worker_state(timeout=0))
        self.assertIsNone(session.process)
        self.assertIsNone(session.reader_thread)

    def test_worker_startup_waits_until_ready_without_timeout(self) -> None:
        session = nct.CaptureSession(dict(nct_config.DEFAULT_CONFIG, output_root=Path("C:/output"), output_path=None))
        process = mock.Mock()
        process.poll.return_value = None
        session.process = process
        session.ready = mock.Mock()
        session.ready.wait.side_effect = [False, False, False, True]
        session._wait_for_worker_ready()
        self.assertEqual(session.ready.wait.call_count, 4)
        session.ready.wait.assert_called_with(0.1)
        self.assertEqual(process.poll.call_count, 3)

    def test_worker_startup_fails_immediately_if_worker_exits(self) -> None:
        session = nct.CaptureSession(dict(nct_config.DEFAULT_CONFIG, output_root=Path("C:/output"), output_path=None))
        process = mock.Mock()
        process.poll.return_value = 7
        process.returncode = 7
        session.process = process
        session.ready = mock.Mock()
        session.ready.wait.return_value = False
        with self.assertRaisesRegex(RuntimeError, "Capture worker exited during startup with code 7"):
            session._wait_for_worker_ready()
        session.ready.wait.assert_called_once_with(0.1)
        process.poll.assert_called_once_with()

    def test_worker_startup_uses_structured_error_received_before_exit(self) -> None:
        session = nct.CaptureSession(dict(nct_config.DEFAULT_CONFIG, output_root=Path("C:/output"), output_path=None))
        process = mock.Mock()
        process.poll.return_value = 1
        process.returncode = 1
        session.process = process
        session.ready = mock.Mock()
        session.ready.wait.return_value = False
        reader = mock.Mock()
        reader.join.side_effect = lambda timeout: setattr(session, "worker_startup_error", "specific startup failure")
        session.reader_thread = reader
        with self.assertRaisesRegex(RuntimeError, "specific startup failure"):
            session._wait_for_worker_ready()
        reader.join.assert_called_once_with(timeout=0.5)

    def test_worker_shutdown_uses_process_tree_fallback_when_job_object_is_unavailable(self) -> None:
        session = nct.CaptureSession(dict(nct_config.DEFAULT_CONFIG, output_root=Path("C:/output"), output_path=None))
        process = mock.Mock()
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired("worker", 3.0), 0]
        session.process = process
        session.worker_job = None
        with mock.patch.object(nct.sys, "platform", "win32"), mock.patch.object(nct_runtime, "terminate_process_tree", return_value=True) as taskkill:
            session._stop_worker()
        process.stdin.write.assert_called_once_with(common.encode_worker_message("shutdown") + "\n")
        process.stdin.flush.assert_called_once_with()
        taskkill.assert_called_once_with(process, timeout=2.0)
        process.kill.assert_not_called()

    def test_empty_session_with_capture_warning_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            session = nct.CaptureSession(options)
            session.session_root = common.create_session_directory(root)
            session.log_path, session.manifest_path = common.session_artifact_paths(root, session.session_root.name)
            capture.initialize_session_manifest(session.session_root, options, session.manifest_path)
            manifest = common.read_json_object(session.manifest_path)
            manifest["capture_errors"] = 1
            common.atomic_write_json(session.manifest_path, manifest)
            session.logger = nct_session.SessionLogger(session.log_path)
            session.started = True
            session_root = session.session_root
            manifest_path = session.manifest_path
            with contextlib.redirect_stdout(io.StringIO()):
                session.cleanup()
            self.assertTrue(session_root.exists())
            self.assertEqual(common.read_json_object(manifest_path)["status"], "completed_with_warnings")

    def test_stale_session_recovery_never_touches_unrelated_temp_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            important = root / "unrelated" / ".temp" / "important.txt"
            important.parent.mkdir(parents=True)
            important.write_text("keep", encoding="utf-8")
            interrupted, warnings = common.recover_stale_sessions(root)
            self.assertEqual((interrupted, warnings), (0, []))
            self.assertEqual(important.read_text(encoding="utf-8"), "keep")

    def test_stale_pending_rotation_session_is_removed_if_never_used(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = root / "pending"
            session.mkdir()
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            log_path, manifest_path = common.session_artifact_paths(root, "pending")
            capture.initialize_session_manifest(session, options, manifest_path, status="pending_rotation")
            interrupted, warnings, recovered = common.recover_stale_session(session)
            self.assertEqual((interrupted, warnings, recovered), (0, [], True))
            self.assertFalse(session.exists())
            self.assertFalse(manifest_path.exists())
            self.assertFalse(log_path.exists())

    def test_stale_pending_rotation_with_payload_is_preserved_as_interrupted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = root / "pending"
            payload = session / "OpenWF" / "Content" / "captured.bin"
            payload.parent.mkdir(parents=True)
            payload.write_bytes(b"data")
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            _, manifest_path = common.session_artifact_paths(root, "pending")
            capture.initialize_session_manifest(session, options, manifest_path, status="pending_rotation")
            interrupted, warnings, recovered = common.recover_stale_session(session)
            self.assertEqual((interrupted, warnings, recovered), (1, [], False))
            self.assertEqual(payload.read_bytes(), b"data")
            self.assertEqual(common.read_json_object(manifest_path)["status"], "interrupted")

    def test_stale_session_recovery_preserves_empty_running_session_for_troubleshooting(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = root / "old"
            session.mkdir()
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            log_path, manifest_path = self.make_sidecar_session_metadata(session, options)
            manifest = common.read_json_object(manifest_path)
            manifest["status"] = "running"
            common.atomic_write_json(manifest_path, manifest)
            log_path.write_text("started\n", encoding="utf-8")
            (session / "OpenWF" / "Content").mkdir(parents=True)
            interrupted, warnings = common.recover_stale_sessions(root)
            self.assertEqual((interrupted, warnings), (1, []))
            self.assertTrue(session.is_dir())
            self.assertEqual(log_path.read_text(encoding="utf-8"), "started\n")
            recovered = common.read_json_object(manifest_path)
            self.assertEqual(recovered["status"], "interrupted")
            self.assertIsNotNone(recovered["finished_at"])

    def test_stale_session_recovery_preserves_empty_starting_session_for_troubleshooting(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = root / "old"
            session.mkdir()
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            _, manifest_path = self.make_sidecar_session_metadata(session, options)
            interrupted, warnings = common.recover_stale_sessions(root)
            self.assertEqual((interrupted, warnings), (1, []))
            self.assertTrue(session.is_dir())
            recovered = common.read_json_object(manifest_path)
            self.assertEqual(recovered["status"], "interrupted")
            self.assertIsNotNone(recovered["finished_at"])

    def test_stale_session_recovery_preserves_completed_empty_session_with_warnings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = root / "old"
            session.mkdir()
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            log_path, manifest_path = self.make_sidecar_session_metadata(session, options)
            manifest = common.read_json_object(manifest_path)
            manifest["status"] = "completed_with_warnings"
            manifest["capture_errors"] = 1
            manifest["finished_at"] = common.current_timestamp()
            common.atomic_write_json(manifest_path, manifest)
            log_path.write_text("Capture completed with warnings.\n", encoding="utf-8")
            interrupted, warnings = common.recover_stale_sessions(root)
            self.assertEqual((interrupted, warnings), (0, []))
            self.assertTrue(session.exists())
            self.assertTrue(log_path.exists())
            self.assertTrue(manifest_path.exists())

    def test_interrupted_session_recovery_reconciles_only_unrecorded_output_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = root / "old"
            content = session / "OpenWF" / "Content" / "0"
            content.mkdir(parents=True)
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            _, manifest_path = self.make_sidecar_session_metadata(session, options)
            known = content / "known.bin"
            orphan = content / "orphan.bin"
            known.write_bytes(b"known")
            orphan.write_bytes(b"orphan")
            manifest = common.read_json_object(manifest_path)
            manifest["status"] = "running"
            manifest["files"] = {
                "0/known.bin": {
                    "size": 5,
                    "sha256": hashlib.sha256(b"known").hexdigest(),
                    "status": 200,
                    "path": "/0/known.bin",
                }
            }
            manifest["captured_files"] = 1
            manifest["captured_bytes"] = 5
            common.atomic_write_json(manifest_path, manifest)

            with mock.patch.object(common, "sha256_file", wraps=common.sha256_file) as hash_file:
                interrupted, warnings = common.recover_stale_sessions(root)
            self.assertEqual((interrupted, warnings), (1, []))
            # Only the file absent from metadata is hashed during reconciliation.
            hash_file.assert_called_once_with(orphan)
            recovered = common.read_json_object(manifest_path)
            self.assertEqual(recovered["status"], "interrupted")
            self.assertEqual(recovered["recovered_files"], 1)
            self.assertEqual(recovered["captured_files"], 2)
            self.assertEqual(recovered["captured_bytes"], 11)
            record = recovered["files"]["0/orphan.bin"]
            self.assertEqual(record["source"], "recovered")
            self.assertNotIn("status", record)
            self.assertEqual(record["sha256"], hashlib.sha256(b"orphan").hexdigest())

    def test_stale_session_recovery_preserves_empty_interrupted_session_on_later_launches(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = root / "old"
            session.mkdir()
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            log_path, manifest_path = self.make_sidecar_session_metadata(session, options)
            manifest = common.read_json_object(manifest_path)
            manifest["status"] = "interrupted"
            manifest["finished_at"] = common.current_timestamp()
            common.atomic_write_json(manifest_path, manifest)
            log_path.write_text("interrupted\n", encoding="utf-8")
            interrupted, warnings = common.recover_stale_sessions(root)
            self.assertEqual((interrupted, warnings), (0, []))
            self.assertTrue(session.is_dir())
            self.assertEqual(log_path.read_text(encoding="utf-8"), "interrupted\n")
            self.assertEqual(common.read_json_object(manifest_path)["status"], "interrupted")

    def test_stale_session_recovery_preserves_unrecorded_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = root / "old"
            (session / "OpenWF" / "Content").mkdir(parents=True)
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            _, manifest_path = self.make_sidecar_session_metadata(session, options)
            manifest = common.read_json_object(manifest_path)
            manifest["status"] = "running"
            common.atomic_write_json(manifest_path, manifest)
            (session / "OpenWF" / "Content" / "captured.bin").write_bytes(b"data")
            interrupted, warnings = common.recover_stale_sessions(root)
            self.assertEqual((interrupted, warnings), (1, []))
            self.assertTrue((session / "OpenWF" / "Content" / "captured.bin").is_file())
            self.assertEqual(common.read_json_object(manifest_path)["status"], "interrupted")

    def test_worker_emits_throttled_saving_progress_after_display_delay(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            store = capture.CaptureStore(session, self.manifest_path_for(session), worker_protocol_enabled=True)
            output = io.StringIO()
            with (
                mock.patch.object(capture.time, "monotonic", side_effect=[100.0, 100.1, 100.6, 100.7]),
                contextlib.redirect_stdout(output),
            ):
                writer = store.begin("https://content.warframe.com/a.bin", 200, expected_size=6)
                writer.feed(b"ab")
                writer.feed(b"cd")
                writer.feed(b"ef")
                writer.feed(b"")
            payloads = [
                message for message in worker_messages(output.getvalue())
                if message.get("type") == "progress" and message.get("action") == "saving"
            ]
            self.assertEqual(len(payloads), 1)
            self.assertEqual(
                payloads[0],
                {"type": "progress", "action": "saving", "received": 4, "expected": 6, "speed_bps": 6, "path": "/a.bin"},
            )

    def test_parent_consumes_worker_saving_progress_without_logging_protocol_line(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            logger = nct_session.SessionLogger(Path(tmp) / "capture.log")
            session = nct.CaptureSession(dict(nct_config.DEFAULT_CONFIG))
            session.logger = logger
            payload = json.dumps(
                {
                    "received": 3 * 1024 * 1024,
                    "expected": 6 * 1024 * 1024,
                    "speed_bps": 2 * 1024 * 1024,
                    "path": "/a.bin",
                }
            )
            process = SimpleNamespace(stdout=io.StringIO(common.encode_worker_message("progress", action="saving", **json.loads(payload)) + "\n"))
            stdout = io.StringIO()
            with (
                mock.patch.object(nct_session.SessionLogger, "_interactive_console", return_value=True),
                mock.patch.object(common, "console_supports_color", return_value=False),
                contextlib.redirect_stdout(stdout),
            ):
                session._read_worker_output(process)
                deadline = time.monotonic() + 1.0
                while "[Saving] 3.0 MiB / 6.0 MiB (50.0%) | 2.0 MiB/s | /a.bin" not in stdout.getvalue():
                    if time.monotonic() >= deadline:
                        break
                    time.sleep(0.01)
                session._stop_worker_console_dispatcher()
                logger.close()
            self.assertIn(
                "[Saving] 3.0 MiB / 6.0 MiB (50.0%) | 2.0 MiB/s | /a.bin",
                stdout.getvalue(),
            )
            self.assertEqual((Path(tmp) / "capture.log").read_text(encoding="utf-8"), "")

    def test_parent_keeps_worker_provenance_out_of_console_but_writes_it_to_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "capture.log"
            logger = nct_session.SessionLogger(log_path)
            session = nct.CaptureSession(dict(nct_config.DEFAULT_CONFIG))
            session.logger = logger
            console_line = "[Saved] 3 B | 200 | /a.bin"
            log_line = console_line + " | Process: Launcher.exe (PID 12345)"
            process = SimpleNamespace(
                stdout=io.StringIO(
                    common.encode_worker_message("output", console=console_line, log=log_line) + "\n"
                )
            )
            stdout = io.StringIO()
            with (
                mock.patch.object(common, "current_timestamp", return_value="2026-09-10T17:42:13+02:00"),
                contextlib.redirect_stdout(stdout),
            ):
                session._read_worker_output(process)
                deadline = time.monotonic() + 1.0
                while console_line not in stdout.getvalue():
                    if time.monotonic() >= deadline:
                        break
                    time.sleep(0.01)
                session._stop_worker_console_dispatcher()
                logger.close()

            self.assertIn(console_line, stdout.getvalue())
            self.assertNotIn("Process: Launcher.exe", stdout.getvalue())
            self.assertEqual(
                log_path.read_text(encoding="utf-8"),
                f"2026-09-10T17:42:13+02:00 {log_line}\n",
            )

    def test_parent_consumes_worker_extracting_progress_without_logging_protocol_line(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            logger = nct_session.SessionLogger(Path(tmp) / "capture.log")
            session = nct.CaptureSession(dict(nct_config.DEFAULT_CONFIG))
            session.logger = logger
            payload = json.dumps(
                {
                    "received": 20 * 1024 * 1024,
                    "expected": 40 * 1024 * 1024,
                    "speed_bps": 80 * 1024 * 1024,
                    "path": "Warframe.x64.exe",
                }
            )
            process = SimpleNamespace(stdout=io.StringIO(common.encode_worker_message("progress", action="extracting", **json.loads(payload)) + "\n"))
            stdout = io.StringIO()
            with (
                mock.patch.object(nct_session.SessionLogger, "_interactive_console", return_value=True),
                mock.patch.object(common, "console_supports_color", return_value=False),
                contextlib.redirect_stdout(stdout),
            ):
                session._read_worker_output(process)
                deadline = time.monotonic() + 1.0
                while "[Extracting] 20.0 MiB / 40.0 MiB (50.0%) | 80.0 MiB/s | Warframe.x64.exe" not in stdout.getvalue():
                    if time.monotonic() >= deadline:
                        break
                    time.sleep(0.01)
                session._stop_worker_console_dispatcher()
                logger.close()
            self.assertIn(
                "[Extracting] 20.0 MiB / 40.0 MiB (50.0%) | 80.0 MiB/s | Warframe.x64.exe",
                stdout.getvalue(),
            )
            self.assertEqual((Path(tmp) / "capture.log").read_text(encoding="utf-8"), "")

    def test_parent_stops_and_marks_session_failed_on_worker_fatal_message(self) -> None:
        session = nct.CaptureSession(dict(nct_config.DEFAULT_CONFIG))
        process = SimpleNamespace(
            stdout=io.StringIO(
                common.encode_worker_message(
                    "fatal",
                    reason="Multiple update states were detected because B.Cache.Windows.bin changed.",
                )
                + "\n"
            )
        )
        session._read_worker_output(process)
        self.assertTrue(session.failed)
        self.assertTrue(session.shutdown_requested.is_set())
        self.assertIn("Multiple update states", str(session.failure_reason))

    def test_blocked_console_does_not_backpressure_worker_pipe_reader(self) -> None:
        class BlockingLogger:
            def __init__(self) -> None:
                self.file_lines: list[str] = []
                self.console_started = threading.Event()
                self.release_console = threading.Event()

            def write(self, message: str, console: bool = True, file: bool = True) -> None:
                if file:
                    self.file_lines.append(message)
                if console:
                    self.console_started.set()
                    self.release_console.wait(2.0)

            def show_progress(self, message: str) -> None:
                self.console_started.set()
                self.release_console.wait(2.0)

            def clear_progress(self) -> None:
                return

        session = nct.CaptureSession(dict(nct_config.DEFAULT_CONFIG))
        logger = BlockingLogger()
        session.logger = logger
        lines = [f"[Debug] worker line {index}" for index in range(3000)]
        process = SimpleNamespace(stdout=io.StringIO("\n".join(lines) + "\n"))
        reader = threading.Thread(target=session._read_worker_output, args=(process,))
        reader.start()
        self.assertTrue(logger.console_started.wait(1.0))
        reader.join(timeout=1.0)
        self.assertFalse(reader.is_alive(), "worker pipe reader was blocked by console rendering")
        self.assertEqual(logger.file_lines, lines)
        self.assertLessEqual(len(session.worker_console_queue), 2048)
        logger.release_console.set()
        session._stop_worker_console_dispatcher(timeout=1.0)

    def test_rotation_handoff_failure_is_propagated_and_keeps_pending_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_session = root / "old"
            new_session = root / "new"
            old_session.mkdir()
            new_session.mkdir()
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            old_log, old_manifest = common.session_artifact_paths(root, "old-meta")
            new_log, new_manifest = common.session_artifact_paths(root, "new-meta")
            capture.initialize_session_manifest(old_session, options, old_manifest, status="running")
            capture.initialize_session_manifest(new_session, options, new_manifest, status="running")
            session = nct.CaptureSession(options)
            session.session_root = old_session
            session.manifest_path = old_manifest
            session.log_path = old_log
            pending = {
                "token": "rotation-token",
                "session_root": new_session,
                "manifest_path": new_manifest,
                "log_path": new_log,
                "temp_root": root / ".temp",
                "old_session_root": old_session,
                "old_manifest_path": old_manifest,
                "old_log_path": old_log,
                "old_temp_root": root / ".temp",
                "old_logger": None,
            }
            session.pending_rotation = pending
            process = SimpleNamespace(
                stdout=io.StringIO(common.encode_worker_message("rotated", token="rotation-token") + "\n")
            )
            with mock.patch.object(nct_session, "SessionLogger", side_effect=OSError("log unavailable")):
                session._read_worker_output(process)
            self.assertTrue(session.reader_failed.is_set())
            self.assertIs(session.pending_rotation, pending)
            self.assertEqual(session.session_root, old_session)
            with self.assertRaisesRegex(RuntimeError, "Capture worker communication failed: log unavailable"):
                session._raise_reader_failure()

    def test_local_capture_result_protocol_records_process_and_pid_only_in_log_variant(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            addon = capture.CaptureAddon(
                session,
                self.manifest_path_for(session),
                worker_protocol_enabled=True,
            )
            flow = self.fake_flow(200, content_length="3")
            flow.client_conn = SimpleNamespace(
                _nct_process_name=r"C:\Games\Warframe\Launcher.exe",
                _nct_process_pid=12345,
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                addon.responseheaders(flow)
                flow.response.stream(b"abc")
                flow.response.stream(b"")

            result = next(
                message
                for message in worker_messages(output.getvalue())
                if message.get("type") == "output"
            )
            self.assertEqual(result["console"], "[Saved] 3 B | 200 | /a.bin")
            self.assertEqual(
                result["log"],
                "[Saved] 3 B | 200 | /a.bin | Process: Launcher.exe (PID 12345)",
            )
            record = common.read_json_object(self.manifest_path_for(session))["files"]["a.bin"]
            self.assertNotIn("process", record)
            self.assertNotIn("process_name", record)
            self.assertNotIn("process_pid", record)

    def test_incomplete_capture_preserves_process_provenance_in_log_and_debug_console(self) -> None:
        for debug, expect_console_provenance in ((False, False), (True, True)):
            with self.subTest(debug=debug), tempfile.TemporaryDirectory() as tmp:
                session = self.make_session(Path(tmp))
                store = capture.CaptureStore(
                    session,
                    self.manifest_path_for(session),
                    debug=debug,
                    worker_protocol_enabled=True,
                )
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    writer = store.begin(
                        "https://content.warframe.com/a.bin",
                        200,
                        expected_size=4,
                        process_name="Launcher.exe",
                        process_pid=12345,
                    )
                    writer.feed(b"abc")
                    writer.feed(b"")

                result = next(
                    message
                    for message in worker_messages(output.getvalue())
                    if message.get("type") == "output" and "Incomplete response" in str(message.get("log"))
                )
                suffix = " | Process: Launcher.exe (PID 12345)"
                self.assertTrue(str(result["log"]).endswith(suffix))
                self.assertEqual(str(result["console"]).endswith(suffix), expect_console_provenance)

    def test_debug_capture_result_includes_process_provenance_in_console_variant(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            addon = capture.CaptureAddon(
                session,
                self.manifest_path_for(session),
                debug=True,
                worker_protocol_enabled=True,
            )
            flow = self.fake_flow(200, content_length="3")
            flow.client_conn = SimpleNamespace(
                _nct_process_name=r"C:\\Games\\Warframe\\Launcher.exe",
                _nct_process_pid=12345,
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                addon.responseheaders(flow)
                flow.response.stream(b"abc")
                flow.response.stream(b"")

            result = next(
                message
                for message in worker_messages(output.getvalue())
                if message.get("type") == "output" and "[Saved]" in str(message.get("console"))
            )
            expected = "[Saved] 3 B | 200 | /a.bin | Process: Launcher.exe (PID 12345)"
            self.assertEqual(result["console"], expected)
            self.assertEqual(result["log"], expected)

    def test_global_debug_capture_result_includes_process_provenance_in_console_variant(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            addon = capture.CaptureAddon(
                session,
                self.manifest_path_for(session),
                debug="global",
                worker_protocol_enabled=True,
            )
            flow = self.fake_flow(200, content_length="3")
            flow.client_conn = SimpleNamespace(
                _nct_process_name=r"C:\\Games\\Warframe\\Warframe.x64.exe",
                _nct_process_pid=67890,
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                addon.responseheaders(flow)
                flow.response.stream(b"abc")
                flow.response.stream(b"")

            result = next(
                message
                for message in worker_messages(output.getvalue())
                if message.get("type") == "output" and "[Saved]" in str(message.get("console"))
            )
            expected = "[Saved] 3 B | 200 | /a.bin | Process: Warframe.x64.exe (PID 67890)"
            self.assertEqual(result["console"], expected)
            self.assertEqual(result["log"], expected)

    def test_debug_nct_owned_capture_results_include_source_provenance_in_console_variant(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            store = capture.CaptureStore(
                session,
                manifest_path=self.manifest_path_for(session),
                debug=True,
                worker_protocol_enabled=True,
            )
            h_cache = make_shcc_container()
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                writer = store.begin(
                    "https://content.warframe.com/0/H.Cache.bin!E_---------------------w",
                    200,
                    len(h_cache),
                    record_metadata={
                        "source": "manual",
                        "source_url": "https://origin.warframe.com/origin/00000000/0/H.Cache.bin!E_---------------------w",
                    },
                )
                writer.feed(h_cache)
                writer.feed(b"")
                store._save_generated_empty_file("0/UNMANAGED", {"h_cache_manifest_type": "E"})

            results = [
                message
                for message in worker_messages(output.getvalue())
                if message.get("type") == "output"
            ]
            h_cache_result = next(message for message in results if "H.Cache.bin" in str(message.get("console")))
            unmanaged_result = next(message for message in results if "/0/UNMANAGED" in str(message.get("console")))
            self.assertTrue(str(h_cache_result["console"]).endswith("| Source: Fetched by Ninja Capture Tool"))
            self.assertEqual(h_cache_result["console"], h_cache_result["log"])
            self.assertTrue(str(unmanaged_result["console"]).endswith("| Source: Generated by Ninja Capture Tool"))
            self.assertEqual(unmanaged_result["console"], unmanaged_result["log"])

    def test_executable_extraction_reports_transient_worker_progress(self) -> None:
        executable = (b"MZ" + bytes(range(256))) * 16384
        expected_md5 = hashlib.md5(executable, usedforsecurity=False).hexdigest().upper()
        compressed = lzma.compress(executable, format=lzma.FORMAT_ALONE)
        name = f"Warframe.x64.exe.{expected_md5}.lzma"
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            archive = session / "OpenWF" / "Content" / name
            archive.parent.mkdir(parents=True, exist_ok=True)
            archive.write_bytes(compressed)
            store = capture.CaptureStore(session, self.manifest_path_for(session), worker_protocol_enabled=True)
            output = io.StringIO()
            with (
                mock.patch.object(store, "_lzma_alone_uncompressed_size", return_value=len(executable)),
                mock.patch.object(capture.time, "monotonic", side_effect=[0.0, 0.6, 0.9, 1.2, 1.5, 1.8]),
                contextlib.redirect_stdout(output),
            ):
                store._extract_executable_if_needed(Path(name), archive)
            progress = [
                message for message in worker_messages(output.getvalue())
                if message.get("type") == "progress" and message.get("action") == "extracting"
            ]
            self.assertTrue(progress)
            self.assertEqual(progress[0]["expected"], len(executable))
            self.assertEqual(progress[0]["path"], "Warframe.x64.exe")
            self.assertGreater(progress[0]["speed_bps"], 0)
            self.assertIn("[Extracted]", output.getvalue())

    def test_capture_store_keeps_manifest_in_memory_after_startup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            store = capture.CaptureStore(session, self.manifest_path_for(session))
            writer = store.begin("https://content.warframe.com/a.bin", 200, 3)
            with mock.patch.object(capture, "read_json_object", side_effect=AssertionError("manifest should not be reread")):
                with contextlib.redirect_stdout(io.StringIO()):
                    writer.feed(b"abc")
                    writer.feed(b"")

    def test_global_debug_running_only_emits_worker_ready_message(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            addon = self.make_addon(Path(tmp), debug="global")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                addon.running()
            lines = [line for line in output.getvalue().splitlines() if line]
            self.assertEqual([common.parse_worker_message(line) for line in lines], [{"type": "ready"}])

    def test_worker_running_marks_manifest_before_ready_message(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            addon = capture.CaptureAddon(session, self.manifest_path_for(session))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                addon.running()
            manifest = json.loads(self.manifest_path_for(session).read_text(encoding="utf-8"))
            self.assertEqual(manifest["status"], "running")
            self.assertIn({"type": "ready"}, worker_messages(output.getvalue()))

    def test_worker_never_announces_ready_when_running_state_cannot_be_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            addon = capture.CaptureAddon(session, self.manifest_path_for(session))
            output = io.StringIO()
            with (
                mock.patch.object(addon.store, "_persist_manifest", return_value=False),
                contextlib.redirect_stdout(output),
                self.assertRaisesRegex(RuntimeError, "running capture state"),
            ):
                addon.running()
            self.assertNotIn({"type": "ready"}, worker_messages(output.getvalue()))

    def test_global_debug_worker_command_uses_machine_wide_local_mode(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, capture_mode="local", debug="global")
        with mock.patch.object(nct.sys, "frozen", False, create=True):
            command = nct_runtime.worker_command(Path("C:/session"), options, manifest_path=Path("C:/session_session.json"))
        self.assertEqual(command[command.index("--mode") + 1], "local")
        self.assertEqual(command[command.index("--debug-worker") + 1], "global")

    def test_worker_failure_prints_traceback_for_capture_log(self) -> None:
        output = io.StringIO()
        def fail_run(coroutine):
            coroutine.close()
            raise RuntimeError("worker boom")
        with mock.patch.object(nct, "install_worker_stop_handler"), mock.patch.object(
            nct.asyncio, "run", side_effect=fail_run
        ), contextlib.redirect_stdout(output):
            result = nct.worker_main(
                ["--proxy-worker", "--session", ".", "--manifest", "session.json", "--mode", "local", "--listen-port", "0", "--debug-worker", "off"]
            )
        self.assertEqual(result, 1)
        self.assertIn("ERROR: Capture worker failed: worker boom", output.getvalue())
        self.assertIn("[Traceback] Traceback", output.getvalue())

    def test_local_worker_reports_windivert_error_654_as_structured_startup_error(self) -> None:
        output = io.StringIO()
        def fail_run(coroutine):
            coroutine.close()
            raise OSError(654, "The driver has failed prior unload")
        with mock.patch.object(nct, "install_worker_stop_handler"), mock.patch.object(
            nct.asyncio, "run", side_effect=fail_run
        ), contextlib.redirect_stdout(output):
            result = nct.worker_main(
                ["--proxy-worker", "--session", ".", "--manifest", "session.json", "--mode", "local", "--listen-port", "0", "--debug-worker", "off"]
            )
        self.assertEqual(result, 1)
        messages = worker_messages(output.getvalue())
        self.assertEqual(len(messages), 1)
        message = messages[0]
        self.assertEqual(message["type"], "startup_error")
        self.assertIn("Windows error 654", str(message["reason"]))
        self.assertIn("sc.exe stop WinDivert", str(message["reason"]))
        self.assertIn("failed prior unload", str(message["detail"]))
        self.assertIn("Traceback", str(message["traceback"]))
        self.assertNotIn("ERROR: Capture worker failed", output.getvalue())

    def test_worker_reader_keeps_structured_startup_traceback_log_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = nct.CaptureSession(dict(nct_config.DEFAULT_CONFIG, output_root=Path(tmp), output_path=None))
            log_path = Path(tmp) / "capture.log"
            session.logger = nct_session.SessionLogger(log_path)
            reason = "Local Capture could not start because an incompatible WinDivert driver is still loaded (Windows error 654)."
            payload = common.encode_worker_message(
                "startup_error",
                reason=reason,
                detail="The driver has failed prior unload (OS error 654)",
                traceback="Traceback (most recent call last):\nRuntimeError: driver failure\n",
            )
            process = SimpleNamespace(stdout=io.StringIO(payload + "\n"))
            console = io.StringIO()
            with contextlib.redirect_stdout(console):
                session._read_worker_output(process)
            session.logger.close()
            self.assertEqual(session.worker_startup_error, reason)
            self.assertEqual(console.getvalue(), "")
            log_text = log_path.read_text(encoding="utf-8")
            self.assertIn("ERROR: " + reason, log_text)
            self.assertIn("[Worker exception] The driver has failed prior unload (OS error 654)", log_text)
            self.assertIn("[Traceback] Traceback (most recent call last):", log_text)
            self.assertIn("[Traceback] RuntimeError: driver failure", log_text)

    def test_backwards_version_report_is_not_used_for_automatic_session_naming(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            options = dict(
                nct_config.DEFAULT_CONFIG,
                output_root=root,
                output_path=None,
                name_session_after_warframe_version=True,
            )
            session = nct.CaptureSession(options)
            with (
                mock.patch.object(live_tracking, "load_warframe_version_high_water", return_value="43.5.5"),
                mock.patch.object(live_tracking, "save_warframe_version_high_water") as save,
            ):
                info, messages = session._apply_current_warframe_version_result(
                    "43.5.4", None, announce_current=True
                )
            save.assert_not_called()
            target, session_id, session_naming = session._create_automatic_session_directory(root, info, messages)
            self.assertNotEqual(target.name, "43.5.4")
            self.assertEqual(target.name, session_id)
            self.assertEqual(session_naming, "timestamp")
            self.assertRegex(target.name, r"^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}(?:_\d+)?$")
            self.assertIn(
                ("info", "[Session] Automatic version naming unavailable; using timestamp session name instead."),
                messages,
            )

    def test_session_manifest_uses_application_version_and_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp) / "session"
            session.mkdir()
            capture.initialize_session_manifest(session, dict(nct_config.DEFAULT_CONFIG, output_root=Path(tmp), output_path=None), self.manifest_path_for(session))
            data = json.loads(self.manifest_path_for(session).read_text(encoding="utf-8"))
            self.assertEqual(data["version"], 1)
            self.assertRegex(data["session_id"], r"^[0-9a-f]{32}$")
            self.assertEqual(data["application_version"], common.VERSION)
            self.assertEqual(data["status"], "starting")
            self.assertEqual(data["capture_mode"], nct_config.DEFAULT_CONFIG["capture_mode"])
            self.assertEqual(data["proxy_port"], nct_config.DEFAULT_CONFIG["proxy_port"])
            self.assertEqual(data["upstream_proxy"], "auto")
            self.assertIs(data["stop_on_exit"], False)
            self.assertEqual(data["stop_on_exit_delay"], nct_config.DEFAULT_CONFIG["stop_on_exit_delay"])
            self.assertIsNone(data["end_reason"])
            self.assertEqual(
                data["capture_config_history"],
                [
                    {
                        "changed_at": data["started_at"],
                        "capture_mode": nct_config.DEFAULT_CONFIG["capture_mode"],
                        "processes": nct_config.DEFAULT_CONFIG["processes"],
                        "debug": "off",
                        "proxy_port": nct_config.DEFAULT_CONFIG["proxy_port"],
                        "upstream_proxy": "auto",
                        "stop_on_exit": False,
                        "stop_on_exit_delay": nct_config.DEFAULT_CONFIG["stop_on_exit_delay"],
                    }
                ],
            )

    def test_capture_session_finalization_uses_recorded_end_reason(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture_root = root / "session"
            capture_root.mkdir()
            manifest_path = self.manifest_path_for(capture_root)
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            capture.initialize_session_manifest(capture_root, options, manifest_path)
            session = nct.CaptureSession(options)
            session.session_root = capture_root
            session.manifest_path = manifest_path
            session.started = True
            session.end_reason = "ctrl_c"

            manifest = session._finalize_session_metadata()
            assert manifest is not None
            self.assertEqual(manifest["status"], "completed")
            self.assertEqual(manifest["end_reason"], "ctrl_c")
            self.assertIsNone(manifest["failure_reason"])

    def test_session_manifest_finalization_records_end_reason_separately_from_failure_reason(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = root / "session"
            session.mkdir()
            manifest_path = self.manifest_path_for(session)
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            capture.initialize_session_manifest(session, options, manifest_path)

            completed = capture.finalize_session_manifest(
                session,
                "completed",
                manifest_path,
                end_reason="ctrl_c",
            )
            self.assertEqual(completed["end_reason"], "ctrl_c")
            self.assertIsNone(completed["failure_reason"])

            failed = capture.finalize_session_manifest(
                session,
                "failed",
                manifest_path,
                "proxy worker failed",
                end_reason="failure",
            )
            self.assertEqual(failed["end_reason"], "failure")
            self.assertEqual(failed["failure_reason"], "proxy worker failed")

    def test_session_manifest_records_explicit_session_naming_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = root / "43.5.4"
            session.mkdir()
            manifest_path = self.manifest_path_for(session)
            capture.initialize_session_manifest(
                session,
                dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None),
                manifest_path,
                session_naming="warframe_version",
            )
            self.assertEqual(common.read_json_object(manifest_path)["session_naming"], "warframe_version")

    def test_shutdown_skips_recursive_payload_scan_when_manifest_already_has_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            session = nct.CaptureSession(options)
            session.session_root = common.create_session_directory(root)
            session.log_path, session.manifest_path = common.session_artifact_paths(root, session.session_root.name)
            capture.initialize_session_manifest(session.session_root, options, session.manifest_path)
            manifest = common.read_json_object(session.manifest_path)
            manifest["captured_files"] = 1
            manifest["captured_bytes"] = 1
            common.atomic_write_json(session.manifest_path, manifest)
            session.logger = nct_session.SessionLogger(session.log_path)
            session.started = True
            with mock.patch.object(common, "session_has_payload", side_effect=AssertionError("recursive scan should be skipped")), contextlib.redirect_stdout(io.StringIO()):
                session.cleanup()
            self.assertTrue(session.session_root.exists())

    def test_worker_ctrl_break_is_handled_gracefully_on_windows(self) -> None:
        handlers = {}

        def register(signum, handler):
            handlers[signum] = handler

        with (
            mock.patch.object(nct.sys, "platform", "win32"),
            mock.patch.object(nct.signal, "SIGBREAK", 99, create=True),
            mock.patch.object(nct.signal, "signal", side_effect=register),
        ):
            nct.install_worker_stop_handler()

        self.assertIn(99, handlers)
        with self.assertRaises(KeyboardInterrupt):
            handlers[99](99, None)

    def test_main_suspends_quick_edit_from_console_start_through_worker_ready(self) -> None:
        events: list[str] = []
        options = dict(nct_config.DEFAULT_CONFIG, capture_mode="local", output_root=Path("output"), output_path=None)
        config = dict(nct_config.DEFAULT_CONFIG)
        session = mock.Mock()
        session.end_reason = None
        session.failed = False
        session.start.side_effect = lambda: events.append("session-start")
        session.wait.side_effect = lambda: events.append("session-wait")
        session.cleanup.side_effect = lambda: events.append("cleanup")

        @contextlib.contextmanager
        def suspend_quick_edit():
            events.append("quickedit-enter")
            try:
                yield
            finally:
                events.append("quickedit-exit")

        with (
            mock.patch.object(nct.sys, "platform", "win32"),
            mock.patch.object(nct, "handle_early_update_request", return_value=None),
            mock.patch.object(elevation, "is_elevated", return_value=True),
            mock.patch.object(elevation, "elevation_task_is_current", return_value=True),
            mock.patch.object(nct, "capture_lock", side_effect=contextlib.nullcontext),
            mock.patch.object(nct, "_restore_interrupted_system_proxy"),
            mock.patch.object(nct, "_warn_stale_update_recovery_backups"),
            mock.patch.object(nct, "_load_startup_config_and_options", return_value=(config, None, options)),
            mock.patch.object(nct_runtime, "show_console_window", side_effect=lambda: events.append("show-console")),
            mock.patch.object(nct_runtime, "suspend_console_quick_edit", side_effect=suspend_quick_edit),
            mock.patch.object(
                nct_config,
                "clean_duplicate_config_processes",
                side_effect=lambda *args, **kwargs: (events.append("clean-duplicates") or (0, None)),
            ),
            mock.patch.object(nct_runtime, "set_console_title", side_effect=lambda mode: events.append("set-title")),
            mock.patch.object(
                nct_runtime,
                "ensure_local_capture_compatible",
                side_effect=lambda runtime_options: events.append("compatibility"),
            ),
            mock.patch.object(
                nct,
                "handle_automatic_update",
                side_effect=lambda *args, **kwargs: (events.append("auto-update") or None),
            ),
            mock.patch.object(
                nct,
                "validate_mitmproxy_installation",
                side_effect=lambda: events.append("validate-mitmproxy"),
            ),
            mock.patch.object(
                nct,
                "validate_windows_capture_package",
                side_effect=lambda: events.append("validate-package"),
            ),
            mock.patch.object(nct, "CaptureSession", return_value=session),
            mock.patch.object(session, "enable_config_reload"),
            mock.patch.object(nct.atexit, "register"),
            mock.patch.object(nct, "install_termination_handlers"),
        ):
            self.assertEqual(nct.main([]), 0)

        self.assertEqual(
            events,
            [
                "show-console",
                "quickedit-enter",
                "clean-duplicates",
                "set-title",
                "compatibility",
                "auto-update",
                "validate-mitmproxy",
                "validate-package",
                "session-start",
                "quickedit-exit",
                "session-wait",
                "cleanup",
            ],
        )

    def test_main_returns_failure_for_fatal_worker_message(self) -> None:
        for mode in ("local", "system-proxy"):
            with self.subTest(mode=mode):
                options = dict(nct_config.DEFAULT_CONFIG, capture_mode=mode, output_root=Path("output"), output_path=None)
                session = nct.CaptureSession(options)
                reason = "B.Cache changed during capture"

                def start():
                    session.started = True
                    process = SimpleNamespace(
                        stdout=io.StringIO(common.encode_worker_message("fatal", reason=reason) + "\n"),
                        poll=lambda: None,
                    )
                    session._read_worker_output(process)

                with contextlib.ExitStack() as stack:
                    stack.enter_context(mock.patch.object(nct.sys, "platform", "win32"))
                    stack.enter_context(mock.patch.object(nct_runtime, "restore_redirected_standard_streams"))
                    stack.enter_context(mock.patch.object(nct_runtime, "show_console_window"))
                    stack.enter_context(mock.patch.object(nct_runtime, "set_console_title"))
                    stack.enter_context(mock.patch.object(nct, "handle_early_update_request", return_value=None))
                    stack.enter_context(mock.patch.object(nct_config, "load_stable_config_snapshot", return_value=(dict(nct_config.DEFAULT_CONFIG), None)))
                    stack.enter_context(mock.patch.object(nct_config, "resolve_runtime_options", return_value=options))
                    stack.enter_context(mock.patch.object(elevation, "is_elevated", return_value=True))
                    stack.enter_context(mock.patch.object(elevation, "elevation_task_is_current", return_value=True))
                    stack.enter_context(mock.patch.object(nct, "capture_lock", side_effect=contextlib.nullcontext))
                    stack.enter_context(mock.patch.object(nct_runtime, "ensure_local_capture_compatible"))
                    stack.enter_context(mock.patch.object(nct, "handle_automatic_update", return_value=None))
                    stack.enter_context(mock.patch.object(nct, "validate_mitmproxy_installation"))
                    stack.enter_context(mock.patch.object(nct, "validate_windows_capture_package"))
                    stack.enter_context(mock.patch.object(nct, "CaptureSession", return_value=session))
                    stack.enter_context(mock.patch.object(nct, "install_termination_handlers"))
                    stack.enter_context(mock.patch.object(nct.atexit, "register"))
                    stack.enter_context(mock.patch.object(session, "enable_config_reload"))
                    stack.enter_context(mock.patch.object(session, "_poll_restart_hotkey"))
                    stack.enter_context(mock.patch.object(session, "start", side_effect=start))
                    cleanup = stack.enter_context(mock.patch.object(session, "cleanup"))
                    self.assertEqual(nct.main(["--capture-mode", mode]), 1)
                cleanup.assert_called_once()
                self.assertTrue(session.failed)
                self.assertEqual(session.failure_reason, reason)

    def test_duplicate_capture_exits_silently_before_uac_or_console(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None)
        with (
            mock.patch.object(nct.sys, "platform", "win32"),
            mock.patch.object(nct_config, "load_stable_config_snapshot", return_value=(dict(nct_config.DEFAULT_CONFIG), None)),
            mock.patch.object(nct_config, "resolve_runtime_options", return_value=options),
            mock.patch.object(elevation, "is_elevated", return_value=False),
            mock.patch.object(nct, "another_capture_is_active", return_value=True),
            mock.patch.object(elevation, "run_elevated_and_wait") as elevate,
            mock.patch.object(elevation, "elevation_task_is_current") as task_current,
            mock.patch.object(elevation, "launch_via_elevation_task") as task_launch,
            mock.patch.object(nct_runtime, "show_console_window") as show_console,
            mock.patch.object(nct, "handle_automatic_update") as handle_update,
            mock.patch.object(nct, "validate_mitmproxy_installation") as validate_runtime,
        ):
            self.assertEqual(nct.main([]), 0)
        elevate.assert_not_called()
        task_current.assert_not_called()
        task_launch.assert_not_called()
        show_console.assert_not_called()
        handle_update.assert_not_called()
        validate_runtime.assert_not_called()

    def test_capture_lock_conflict_exits_before_console_for_capture_processes(self) -> None:
        @contextlib.contextmanager
        def conflicting_lock():
            raise nct.CaptureBusyError("Another Ninja Capture Tool capture is already running.")
            yield

        for mode in ("local", "system-proxy"):
            with self.subTest(mode=mode):
                options = dict(
                    nct_config.DEFAULT_CONFIG,
                    capture_mode=mode,
                    output_root=Path("output"),
                    output_path=None,
                )
                with (
                    mock.patch.object(nct.sys, "platform", "win32"),
                    mock.patch.object(nct_config, "load_stable_config_snapshot", return_value=(dict(nct_config.DEFAULT_CONFIG), None)),
                    mock.patch.object(nct_config, "resolve_runtime_options", return_value=options),
                    mock.patch.object(elevation, "is_elevated", return_value=True),
                    mock.patch.object(nct, "capture_lock", side_effect=conflicting_lock),
                    mock.patch.object(nct_runtime, "show_console_window") as show_console,
                    mock.patch.object(nct, "handle_automatic_update") as handle_update,
                ):
                    self.assertEqual(nct.main([]), 0)
                show_console.assert_not_called()
                handle_update.assert_not_called()

    def test_capture_lock_uses_user_and_installation_locks_on_windows(self) -> None:
        calls = []

        @contextlib.contextmanager
        def fake_file_lock(path, timeout_seconds, timeout_message):
            calls.append((path, timeout_seconds, timeout_message))
            yield

        with tempfile.TemporaryDirectory() as tmp:
            local_root = Path(tmp) / "DarkLotus" / "Ninja Capture Tool"
            user_lock = local_root / "locks" / ".capture.lock"
            install_lock = local_root / "locks" / "installation.capture.lock"
            with (
                mock.patch.object(instance_lock, "os", SimpleNamespace(name="nt")),
                mock.patch.object(instance_lock, "user_capture_activity_lock_path", return_value=user_lock),
                mock.patch.object(instance_lock, "capture_activity_lock_path", return_value=install_lock),
                mock.patch.object(instance_lock, "windows_file_lock", side_effect=fake_file_lock),
            ):
                with nct.capture_lock():
                    pass

        self.assertEqual([call[0] for call in calls], [user_lock, install_lock])
        self.assertEqual([call[1] for call in calls], [0, 0])

    def test_first_run_setup_messages_are_grouped_after_session_header(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            requested = root / "capture"
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=requested)
            session = nct.CaptureSession(options, ["Elevation task installed successfully."])
            stdout = io.StringIO()
            order: list[str] = []
            with (
                mock.patch.object(windows_proxy, "restore_stale_recovery", return_value=None),
                mock.patch.object(common, "prepare_runtime_state_directory"),
                mock.patch.object(common, "prepare_output_directory", return_value=2 * 1024 * 1024 * 1024),
                mock.patch.object(session, "_start_worker", side_effect=lambda *args: order.append("worker")),
                mock.patch.object(session, "_wait_for_worker_ready"),
                mock.patch.object(nct_runtime, "ensure_mitmproxy_ca_trusted", side_effect=lambda: order.append("certificate") or True),
                contextlib.redirect_stdout(stdout),
            ):
                session.start()
            self.assertEqual(order, ["certificate", "worker"])
            assert session.logger is not None
            session.logger.close()
            output = stdout.getvalue()
            self.assertNotIn(f"Ninja Capture Tool v{common.display_version()}", output)
            self.assertTrue(output.startswith("[Notice] Update Patch creation supports Warframe Hotfixes only;"))
            self.assertIn("~U43.5.1 / 4895911296145320793 -> U43.5.4, while U43.6 or U44 requires a newer base", output)
            self.assertLess(output.index("[Warframe] Checking live version..."), output.index("[Steam] Checking live manifest..."))
            self.assertLess(output.index("[Steam] Checking live manifest..."), output.index("Session: "))
            self.assertLess(output.index("Session: "), output.index("Mode: Local Capture"))
            self.assertLess(output.index("Mode: Local Capture"), output.index("Debug: Off"))
            self.assertLess(output.index("Debug: Off"), output.index("Elevation task installed successfully."))
            self.assertIn(
                "Elevation task installed successfully.\nHTTPS certificate installed successfully.\n\nCapture is active.",
                output,
            )
            assert session.log_path is not None
            log = session.log_path.read_text(encoding="utf-8")
            self.assertIn("Elevation task installed successfully.", log)
            self.assertIn("HTTPS certificate installed successfully.", log)
