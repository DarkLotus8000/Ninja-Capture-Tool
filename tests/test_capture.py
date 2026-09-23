# Run from the project root with: py -B -m unittest discover -s tests
from support import *

class CaptureTests(NctTestBase):
    def test_same_logical_b_cache_hash_change_stops_mixed_update_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp) / "session"
            session.mkdir()
            manifest_path = self.manifest_path_for(session)
            capture.initialize_session_manifest(session, nct_config.DEFAULT_CONFIG, manifest_path)
            store = capture.CaptureStore(session, manifest_path, worker_protocol_enabled=True)
            store._h_cache_fetch_started = True
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                store.maybe_fetch_official_h_cache("/0/B.Cache.Windows.bin!E_oldHash")
                store.maybe_fetch_official_h_cache("/0/B.Cache.Windows.bin!E_newHash")

            manifest = common.read_json_object(manifest_path)
            self.assertTrue(manifest["update_transition_detected"])
            self.assertEqual(
                manifest["manifest_transitions"],
                [{
                    "name": "B.Cache.Windows.bin",
                    "previous_type": "E",
                    "previous_hash": "oldHash",
                    "new_type": "E",
                    "new_hash": "newHash",
                }],
            )
            self.assertTrue(store.capture_disabled)
            self.assertTrue(store.drain_requested.is_set())
            self.assertIn(
                "WARNING: B.Cache.Windows.bin changed during the same capture (oldHash -> newHash).",
                output.getvalue(),
            )
            self.assertIn(
                "ERROR: Multiple update states were detected. Ninja Capture Tool is stopping this session; "
                "start a new session for the current update.",
                output.getvalue(),
            )
            fatal = [message for message in worker_messages(output.getvalue()) if message.get("type") == "fatal"]
            self.assertEqual(len(fatal), 1)
            self.assertIn("B.Cache.Windows.bin changed", str(fatal[0].get("reason")))

    def test_worker_restart_preserves_b_cache_update_baseline(self) -> None:
        for next_path in (
            "/0/B.Cache.Windows.bin!E_newHash",
            "/0/B.Cache.WindowsDx12.bin!F_otherHash",
        ):
            with self.subTest(next_path=next_path), tempfile.TemporaryDirectory() as tmp:
                session = Path(tmp) / "session"
                session.mkdir()
                manifest_path = self.manifest_path_for(session)
                capture.initialize_session_manifest(session, nct_config.DEFAULT_CONFIG, manifest_path)
                store = capture.CaptureStore(session, manifest_path)
                store._h_cache_fetch_started = True
                writer = store.begin("https://content.warframe.com/0/B.Cache.Windows.bin!E_oldHash", 200, 3)
                writer.feed(b"old")
                writer.feed(b"")
                store.abort_all()

                restarted = capture.CaptureStore(session, manifest_path, worker_protocol_enabled=True)
                self.addCleanup(restarted.abort_all)
                restarted._h_cache_fetch_started = True
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    writer = restarted.begin("https://content.warframe.com" + next_path, 200, 3)
                    writer.feed(b"new")
                    writer.feed(b"")
                self.assertTrue(restarted.capture_disabled)
                self.assertTrue(common.read_json_object(manifest_path)["update_transition_detected"])
                self.assertEqual(len([m for m in worker_messages(output.getvalue()) if m["type"] == "fatal"]), 1)
                restarted.abort_all()

    def test_target_host_must_match_exactly(self) -> None:
        self.assertTrue(capture.is_target_request("content.warframe.com", "https://content.warframe.com/foo"))
        self.assertTrue(capture.is_target_request("CONTENT.WARFRAME.COM", "https://CONTENT.WARFRAME.COM/foo"))
        for host, url in (
            ("warframe.com", "https://warframe.com/foo"),
            ("forums.warframe.com", "https://forums.warframe.com/foo"),
            ("foo.warframe.com", "https://foo.warframe.com/foo"),
            ("evilcontent.warframe.com", "https://evilcontent.warframe.com/foo"),
            ("content.warframe.com.evil.test", "https://content.warframe.com.evil.test/foo"),
            ("example.com", "https://example.com/content.warframe.com/foo"),
            ("content.warframe.com", "https://example.com/foo"),
        ):
            with self.subTest(host=host, url=url):
                self.assertFalse(capture.is_target_request(host, url))

    def test_allow_hosts_regex_is_anchored(self) -> None:
        pattern = re.compile(common.ALLOW_HOSTS_REGEX, re.I)
        self.assertTrue(pattern.fullmatch("content.warframe.com"))
        self.assertTrue(pattern.fullmatch("content.warframe.com:443"))
        self.assertFalse(pattern.fullmatch("foo.content.warframe.com"))
        self.assertFalse(pattern.fullmatch("content.warframe.com.evil.test"))

    def test_debug_host_never_includes_path_or_query(self) -> None:
        self.assertEqual(capture.debug_host("https://example.com/private/reset?token=secret"), "example.com")

    def test_capture_path_preserves_normal_hierarchy(self) -> None:
        self.assertEqual(
            capture.capture_relative_path("https://content.warframe.com/Cache.Windows/Foo.cache"),
            Path("Cache.Windows") / "Foo.cache",
        )

    def test_capture_path_neutralizes_traversal_and_windows_reserved_names(self) -> None:
        self.assertEqual(
            capture.capture_relative_path("https://content.warframe.com/../CON/file:name"),
            Path("%2E%2E") / "%5FCON" / "file%3Aname",
        )

    def test_capture_root_and_directory_urls_have_files(self) -> None:
        self.assertEqual(capture.capture_relative_path("https://content.warframe.com/"), Path("~root"))
        self.assertEqual(capture.capture_relative_path("https://content.warframe.com/folder/"), Path("folder") / "~index")

    def test_capture_path_encoding_is_injective_for_escaped_and_synthetic_components(self) -> None:
        pairs = (
            ("/foo:bar", "/foo%3Abar"),
            ("/.", "/%2E"),
            ("/folder/", "/folder/~index"),
            ("/a//b", "/a/b"),
            ("/", "/~root"),
        )
        for left, right in pairs:
            with self.subTest(left=left, right=right):
                left_path = capture.capture_relative_path(f"https://content.warframe.com{left}")
                right_path = capture.capture_relative_path(f"https://content.warframe.com{right}")
                self.assertNotEqual(left_path, right_path)

    def test_capture_path_handles_additional_windows_reserved_device_names(self) -> None:
        self.assertEqual(capture.safe_path_segment("CONIN$.txt"), "%5FCONIN$.txt")
        self.assertEqual(capture.safe_path_segment("CONOUT$"), "%5FCONOUT$")
        self.assertEqual(capture.safe_path_segment("COM¹.log"), "%5FCOM¹.log")
        self.assertEqual(capture.safe_path_segment("LPT²"), "%5FLPT²")

    def test_long_path_segment_is_preserved_exactly(self) -> None:
        original = "a" * 240 + ".cache"
        self.assertEqual(capture.capture_relative_path(f"https://content.warframe.com/{original}").name, original)

    def test_unrepresentable_path_segment_is_rejected_instead_of_renamed(self) -> None:
        original = "a" * 256
        with self.assertRaisesRegex(ValueError, "cannot be preserved exactly"):
            capture.capture_relative_path(f"https://content.warframe.com/{original}")

    def test_atomic_json_writes_do_not_share_temporary_files_between_threads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            errors: list[BaseException] = []
            barrier = threading.Barrier(8)
            replace_guard = threading.Lock()
            original_replace = os.replace

            def windows_like_replace(source, destination):
                if not replace_guard.acquire(blocking=False):
                    raise PermissionError(errno.EACCES, "simulated concurrent Windows replace")
                try:
                    time.sleep(0.001)
                    return original_replace(source, destination)
                finally:
                    replace_guard.release()

            def writer(index: int) -> None:
                try:
                    barrier.wait()
                    for value in range(25):
                        common.atomic_write_json(path, {"writer": index, "value": value})
                except BaseException as exc:
                    errors.append(exc)

            with mock.patch.object(common.os, "replace", side_effect=windows_like_replace):
                threads = [threading.Thread(target=writer, args=(index,)) for index in range(8)]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join()
            self.assertEqual(errors, [])
            self.assertEqual(set(common.read_json_object(path)), {"writer", "value"})
            self.assertEqual(list(Path(tmp).glob("*.tmp")), [])

            with (
                mock.patch.object(Path, "write_text", side_effect=RuntimeError("primary write failure")),
                mock.patch.object(Path, "unlink", side_effect=OSError("cleanup failure")),
            ):
                with self.assertRaisesRegex(RuntimeError, "primary write failure"):
                    common.atomic_write_json(path, {"value": 1})

    def test_default_capture_mode_is_local(self) -> None:
        self.assertEqual(nct_config.DEFAULT_CONFIG["capture_mode"], "local")
        self.assertEqual(nct_config.DEFAULT_CONFIG["processes"], ["Launcher.exe", "Warframe.x64.exe"])
        self.assertFalse(nct_config.DEFAULT_CONFIG["stop_on_exit"])
        self.assertEqual(nct_config.DEFAULT_CONFIG["stop_on_exit_delay"], 15)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "Duplicate JSON key"):
            nct_config.parse_json('{"a": 1, "a": 2}')
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text('{"debug": false, "debug": true}', encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "Duplicate JSON key"):
                nct_config.load_config(path)

    def test_nonstandard_json_constants_are_rejected(self) -> None:
        for payload in ('{"value": NaN}', '{"value": Infinity}', '{"value": -Infinity}'):
            with self.subTest(payload=payload):
                with self.assertRaisesRegex(ValueError, "Non-standard JSON constant"):
                    nct_config.parse_json(payload)

    def test_windivert_driver_loaded_recognizes_running_stopped_and_missing_service(self) -> None:
        cases = (
            (0, b"STATE              : 4  RUNNING\r\n", b"", True),
            (0, b"STATE              : 1  STOPPED\r\n", b"", False),
            (1060, b"", b"OpenService FAILED 1060", False),
        )
        for returncode, stdout, stderr, expected in cases:
            with self.subTest(returncode=returncode, stdout=stdout):
                result = SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)
                with (
                    mock.patch.object(nct_runtime.sys, "platform", "win32"),
                    mock.patch.object(nct.subprocess, "run", return_value=result),
                ):
                    self.assertEqual(nct._windivert_driver_loaded(), expected)

    def test_windivert_driver_loaded_fails_safe_when_status_is_unknown(self) -> None:
        result = SimpleNamespace(returncode=0, stdout=b"unexpected output", stderr=b"")
        with (
            mock.patch.object(nct_runtime.sys, "platform", "win32"),
            mock.patch.object(nct.subprocess, "run", return_value=result),
        ):
            self.assertTrue(nct._windivert_driver_loaded())

    def test_windivert_prior_unload_detection_follows_exception_chain(self) -> None:
        try:
            try:
                raise OSError(654, "The driver has failed prior unload")
            except OSError as inner:
                raise RuntimeError("redirector startup failed") from inner
        except RuntimeError as exc:
            self.assertTrue(nct._is_windivert_prior_unload_error(exc))

    def test_windivert_prior_unload_detection_accepts_os_error_text_but_not_unrelated_number(self) -> None:
        self.assertTrue(nct._is_windivert_prior_unload_error(RuntimeError("redirector failed: OS error 654")))
        self.assertFalse(nct._is_windivert_prior_unload_error(RuntimeError("copied 654 bytes")))

    def test_live_persistent_invalid_json_reports_only_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            common.atomic_write_json(path, nct_config.DEFAULT_CONFIG)
            args = nct_config.build_argument_parser().parse_args([])
            options = nct_config.resolve_runtime_options(args, dict(nct_config.DEFAULT_CONFIG))
            session = nct.CaptureSession(options)
            session.enable_config_reload(args, path)
            path.write_text('{"debug":', encoding="utf-8")

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertFalse(session._poll_config_reload(now=10.0))
                self.assertFalse(session._poll_config_reload(now=11.0))
                self.assertFalse(session._poll_config_reload(now=12.0))
                self.assertFalse(session._poll_config_reload(now=13.0))

            self.assertEqual(output.getvalue().count("[Config] Reload rejected: invalid JSON:"), 1)
            self.assertTrue(session.config_rejected_signature_set)
            self.assertEqual(session.config_rejected_signature, nct_config.config_file_signature(path))

    def test_running_capture_batches_manifest_writes_and_periodically_flushes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            store = capture.CaptureStore(session, self.manifest_path_for(session))
            with (
                mock.patch.object(capture, "MANIFEST_FLUSH_INTERVAL_SECONDS", 0.01),
                mock.patch.object(capture, "atomic_write_json") as write_json,
            ):
                store.start_metadata_flusher()
                for _ in range(5):
                    store.record_skipped_http()
                self.assertEqual(write_json.call_count, 0)
                time.sleep(0.05)
                self.assertGreaterEqual(write_json.call_count, 1)
                store.close_metadata()

    def test_live_reload_rejects_a_b_a_snapshot_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            common.atomic_write_json(path, nct_config.DEFAULT_CONFIG)
            args = nct_config.build_argument_parser().parse_args([])
            options = nct_config.resolve_runtime_options(args, dict(nct_config.DEFAULT_CONFIG))
            session = nct.CaptureSession(options)
            session.enable_config_reload(args, path)

            changed = dict(nct_config.DEFAULT_CONFIG)
            changed["debug"] = True
            common.atomic_write_json(path, changed)
            with (
                mock.patch.object(nct_config, "load_exact_config_snapshot", side_effect=nct_config.ConfigSnapshotChanged),
                mock.patch.object(session, "_apply_reloaded_config") as apply_config,
            ):
                self.assertFalse(session._poll_config_reload(now=10.0))
                self.assertFalse(session._poll_config_reload(now=11.0))
            apply_config.assert_not_called()
            self.assertEqual(session.options["debug"], False)

    def test_live_reload_cleans_duplicate_processes_without_reloading_its_own_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            common.atomic_write_json(path, nct_config.DEFAULT_CONFIG)
            args = nct_config.build_argument_parser().parse_args([])
            options = nct_config.resolve_runtime_options(args, dict(nct_config.DEFAULT_CONFIG))
            session = nct.CaptureSession(options)
            session.enable_config_reload(args, path)

            config = dict(nct_config.DEFAULT_CONFIG)
            config["processes"] = ["Launcher.exe", "Warframe.x64.exe", "Launcher.exe"]
            common.atomic_write_json(path, config)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertFalse(session._poll_config_reload(now=10.0))
                self.assertFalse(session._poll_config_reload(now=11.0))
                # Ninja Capture Tool's own atomic cleanup write must already be marked processed.
                self.assertFalse(session._poll_config_reload(now=12.0))

            cleaned = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(cleaned["processes"], ["Launcher.exe", "Warframe.x64.exe"])
            text = output.getvalue()
            self.assertEqual(text.count("Duplicate process entry detected"), 1)
            self.assertEqual(text.count("Removed 1 duplicate process entry"), 1)
            self.assertNotIn("[Config] Change detected.", text)
            self.assertTrue(text.endswith("\n\n"))

    def test_live_reload_sequence_recovers_after_invalid_json_and_coalesces_each_save(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            common.atomic_write_json(path, nct_config.DEFAULT_CONFIG)
            args = nct_config.build_argument_parser().parse_args([])
            options = nct_config.resolve_runtime_options(args, dict(nct_config.DEFAULT_CONFIG))
            session = nct.CaptureSession(options)
            session.enable_config_reload(args, path)

            def apply_worker(new_options):
                session.options = dict(new_options)

            def apply_subsystem(new_options):
                session.options = dict(new_options)

            with (
                mock.patch.object(session, "_drain_worker_before_restart"),
                mock.patch.object(session, "_restart_worker_for_options", side_effect=apply_worker) as restart_worker,
                mock.patch.object(session, "_restart_capture_subsystem", side_effect=apply_subsystem) as restart_subsystem,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                path.write_text('{"debug":', encoding="utf-8")
                self.assertFalse(session._poll_config_reload(now=10.0))
                self.assertFalse(session._poll_config_reload(now=11.0))

                config = dict(nct_config.DEFAULT_CONFIG)
                config["debug"] = True
                common.atomic_write_json(path, config)
                self.assertFalse(session._poll_config_reload(now=12.0))
                self.assertFalse(session._poll_config_reload(now=13.0))

                config["processes"] = ["Launcher.exe", "OtherGame.exe"]
                common.atomic_write_json(path, config)
                self.assertFalse(session._poll_config_reload(now=14.0))
                self.assertFalse(session._poll_config_reload(now=15.0))

                config["capture_mode"] = "system-proxy"
                common.atomic_write_json(path, config)
                self.assertFalse(session._poll_config_reload(now=16.0))
                self.assertFalse(session._poll_config_reload(now=17.0))

            self.assertEqual(restart_worker.call_count, 2)
            self.assertEqual(restart_subsystem.call_count, 1)
            self.assertEqual(session.options["capture_mode"], "system-proxy")
            self.assertEqual(session.options["processes"], ["Launcher.exe", "OtherGame.exe"])
            self.assertIs(session.options["debug"], True)

    def test_live_capture_mode_change_restarts_capture_subsystem(self) -> None:
        args = nct_config.build_argument_parser().parse_args([])
        options = nct_config.resolve_runtime_options(args, dict(nct_config.DEFAULT_CONFIG))
        session = nct.CaptureSession(options, cli_args=args)
        config = dict(nct_config.DEFAULT_CONFIG)
        config["capture_mode"] = "system-proxy"
        output = io.StringIO()
        with (
            mock.patch.object(session, "_restart_capture_subsystem") as restart_subsystem,
            mock.patch.object(session, "_sync_session_capture_config_metadata") as sync_metadata,
            mock.patch.object(nct_runtime, "set_console_title") as set_title,
            contextlib.redirect_stdout(output),
        ):
            self.assertFalse(session._apply_reloaded_config(config))
        restart_subsystem.assert_called_once()
        sync_metadata.assert_called_once_with(mock.ANY)
        self.assertEqual(sync_metadata.call_args.args[0]["capture_mode"], "system-proxy")
        set_title.assert_called_once_with("system-proxy")
        text = output.getvalue()
        self.assertIn("[Config] Capture mode: Local -> System Proxy", text)
        self.assertIn("Restarting capture subsystem to apply changes...", text)
        self.assertIn("Capture subsystem restarted successfully.", text)
        self.assertTrue(text.endswith("\n\n"))

    def test_all_public_long_options_have_short_aliases(self) -> None:
        parser = nct_config.build_argument_parser()
        for action in parser._actions:
            long_options = [option for option in action.option_strings if option.startswith("--")]
            if not long_options:
                continue
            short_options = [option for option in action.option_strings if option.startswith("-") and not option.startswith("--")]
            self.assertTrue(short_options, f"Missing short alias for {', '.join(long_options)}")

    def test_process_option_remains_intentionally_repeatable_across_aliases(self) -> None:
        parser = nct_config.build_argument_parser()
        args = parser.parse_args(["-p", "Launcher.exe", "--process", "Warframe.x64.exe"])
        self.assertEqual(args.process, ["Launcher.exe", "Warframe.x64.exe"])

    def test_output_preflight_checks_writability_and_returns_free_space(self) -> None:
        DiskUsage = namedtuple("usage", "total used free")
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            common.shutil, "disk_usage", return_value=DiskUsage(100, 20, 80)
        ):
            root = Path(tmp) / "output"
            self.assertEqual(common.prepare_output_directory(root), 80)
            self.assertTrue(root.is_dir())
            self.assertFalse(any(root.glob(".nct-write-test-*.tmp")))

    def test_localized_b_cache_triggers_manual_h_cache_and_unmanaged(self) -> None:
        class FakeResponse(io.BytesIO):
            status = 200

            def __init__(self, data: bytes):
                super().__init__(data)
                self.headers = {"content-length": str(len(data))}

            def getcode(self):
                return self.status

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                self.close()
                return False

        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp) / "session"
            session.mkdir()
            manifest_path = self.manifest_path_for(session)
            capture.initialize_session_manifest(session, nct_config.DEFAULT_CONFIG, manifest_path)
            store = capture.CaptureStore(session, manifest_path)
            official = make_shcc_container(b"official-h-cache")
            opener = SimpleNamespace(open=mock.Mock(return_value=FakeResponse(official)))
            output = io.StringIO()

            with (
                mock.patch.object(capture.urllib_request, "build_opener", return_value=opener),
                contextlib.redirect_stdout(output),
            ):
                store.maybe_fetch_official_h_cache("/0/B.Cache.Windows_zh.bin!E_localizedHash")
                assert store._h_cache_fetch_thread is not None
                store._h_cache_fetch_thread.join(timeout=1)
                self.assertFalse(store._h_cache_fetch_thread.is_alive())

            h_cache = session / "OpenWF" / "Content" / "0" / "H.Cache.bin!E_---------------------w"
            unmanaged = session / "OpenWF" / "Content" / "0" / "UNMANAGED"
            self.assertEqual(h_cache.read_bytes(), official)
            self.assertTrue(unmanaged.is_file())
            self.assertEqual(unmanaged.stat().st_size, 0)
            request = opener.open.call_args.args[0]
            self.assertEqual(
                request.full_url,
                "https://origin.warframe.com/origin/00000000/0/H.Cache.bin!E_---------------------w",
            )
            self.assertEqual(opener.open.call_args.kwargs["timeout"], 10)
            self.assertEqual(request.get_header("Accept-encoding"), "identity")
            self.assertEqual(request.get_header("User-agent"), capture.MANUAL_H_CACHE_USER_AGENT)
            self.assertTrue(request.get_header("User-agent").startswith("Mozilla/5.0 "))
            self.assertIn("Chrome/", request.get_header("User-agent"))
            self.assertNotIn("NinjaCaptureTool", repr(request.header_items()))
            manifest = common.read_json_object(manifest_path)
            h_cache_record = manifest["files"]["0/H.Cache.bin!E_---------------------w"]
            self.assertEqual(h_cache_record["status"], 200)
            self.assertEqual(h_cache_record["source"], "manual")
            self.assertEqual(
                h_cache_record["source_url"],
                "https://origin.warframe.com/origin/00000000/0/H.Cache.bin!E_---------------------w",
            )
            self.assertTrue(h_cache_record["h_cache_validated"])
            self.assertEqual(h_cache_record["h_cache_validation_method"], "shcc_container_crc32c")
            self.assertNotIn("h_cache_validation_error", h_cache_record)
            self.assertEqual(manifest["files"]["0/UNMANAGED"]["source"], "generated")
            self.assertEqual(manifest["files"]["0/UNMANAGED"]["h_cache_manifest_type"], "E")
            self.assertIn(
                f"[Saved] {len(official)} B | 200 | /0/H.Cache.bin!E_---------------------w",
                output.getvalue(),
            )
            self.assertIn("[Saved] 0 B | OK | /0/UNMANAGED", output.getvalue())
            self.assertNotIn("status", manifest["files"]["0/UNMANAGED"])

    def test_manual_h_cache_provenance_exists_before_h_cache_postprocessing(self) -> None:
        class FakeResponse:
            status = 200

            def __init__(self, payload: bytes):
                self.payload = io.BytesIO(payload)
                self.headers = {"Content-Length": str(len(payload))}

            def read(self, size: int = -1) -> bytes:
                return self.payload.read(size)

            def getcode(self):
                return self.status

            def geturl(self):
                return "https://origin.warframe.com/origin/00000000/0/H.Cache.bin!E_---------------------w"

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp) / "session"
            session.mkdir()
            manifest_path = self.manifest_path_for(session)
            capture.initialize_session_manifest(session, nct_config.DEFAULT_CONFIG, manifest_path)
            store = capture.CaptureStore(session, manifest_path)
            official = make_shcc_container(b"official-h-cache")
            opener = SimpleNamespace(open=mock.Mock(return_value=FakeResponse(official)))
            observed: list[dict[str, object]] = []

            def inspect_before_postprocessing(filename: str) -> bool:
                with store.lock:
                    record = store.files["0/H.Cache.bin!E_---------------------w"]
                    observed.append(dict(record))
                return False

            with (
                mock.patch.object(capture.urllib_request, "build_opener", return_value=opener),
                mock.patch.object(store, "_validate_h_cache_for_unmanaged", side_effect=inspect_before_postprocessing),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                store.maybe_fetch_official_h_cache("/0/B.Cache.Windows_zh.bin!E_hash")
                assert store._h_cache_fetch_thread is not None
                store._h_cache_fetch_thread.join(timeout=1)
                self.assertFalse(store._h_cache_fetch_thread.is_alive())

            self.assertTrue(observed)
            first_record = observed[0]
            self.assertEqual(first_record["source"], "manual")
            self.assertEqual(
                first_record["source_url"],
                "https://origin.warframe.com/origin/00000000/0/H.Cache.bin!E_---------------------w",
            )

    def test_direct_h_cache_is_preferred_and_uses_shcc_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp) / "session"
            session.mkdir()
            manifest_path = self.manifest_path_for(session)
            capture.initialize_session_manifest(session, nct_config.DEFAULT_CONFIG, manifest_path)
            store = capture.CaptureStore(session, manifest_path)
            official = make_shcc_container(b"same-official-h-cache")
            capture_url = "https://content.warframe.com/0/H.Cache.bin!E_---------------------w"
            direct = store.begin(capture_url, 200, len(official))
            direct.feed(official)
            direct.feed(b"")
            opener = SimpleNamespace(open=mock.Mock())
            with mock.patch.object(capture.urllib_request, "build_opener", return_value=opener):
                store.maybe_fetch_official_h_cache("/0/B.Cache.Windows_zh.bin!E_hash")
                assert store._h_cache_fetch_thread is not None
                store._h_cache_fetch_thread.join(timeout=1)

            manifest = common.read_json_object(manifest_path)
            record = manifest["files"]["0/H.Cache.bin!E_---------------------w"]
            self.assertEqual(record["source"], "captured")
            self.assertTrue(record["h_cache_validated"])
            self.assertEqual(record["h_cache_validation_method"], "shcc_container_crc32c")
            self.assertNotIn("source_url", record)
            self.assertNotIn("h_cache_observed_before_b_cache_windows", record)
            self.assertNotIn("correlated_b_cache_windows_hash", record)
            self.assertEqual(manifest["duplicates"], 0)
            self.assertEqual(manifest["files"]["0/UNMANAGED"]["source"], "generated")
            opener.open.assert_not_called()

    def test_later_conflicting_direct_h_cache_removes_generated_unmanaged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp) / "session"
            session.mkdir()
            manifest_path = self.manifest_path_for(session)
            capture.initialize_session_manifest(session, nct_config.DEFAULT_CONFIG, manifest_path)
            store = capture.CaptureStore(session, manifest_path)
            capture_url = "https://content.warframe.com/0/H.Cache.bin!E_---------------------w"
            original = make_shcc_container(b"original")
            direct = store.begin(capture_url, 200, len(original))
            direct.feed(original)
            direct.feed(b"")
            store.maybe_fetch_official_h_cache("/0/B.Cache.Windows_zh.bin!E_hash")
            assert store._h_cache_fetch_thread is not None
            store._h_cache_fetch_thread.join(timeout=1)

            unmanaged = session / "OpenWF" / "Content" / "0" / "UNMANAGED"
            self.assertTrue(unmanaged.exists())
            different = make_shcc_container(b"different")
            conflicting = store.begin(capture_url, 200, len(different))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                conflicting.feed(different)
                conflicting.feed(b"")

            manifest = common.read_json_object(manifest_path)
            self.assertEqual(manifest["conflict_count"], 1)
            self.assertFalse(unmanaged.exists())
            self.assertTrue(store._h_cache_content_conflict)
            self.assertIn(
                "WARNING: Conflicting H.Cache.bin versions were captured; UNMANAGED was not created.",
                output.getvalue(),
            )

    def test_manual_h_cache_fetch_rejects_shcc_magic_without_payload(self) -> None:
        class FakeResponse(io.BytesIO):
            status = 200

            def __init__(self):
                super().__init__(b"SHCC")
                self.headers = {"content-length": "4"}

            def getcode(self):
                return self.status

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                self.close()
                return False

        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp) / "session"
            session.mkdir()
            manifest_path = self.manifest_path_for(session)
            capture.initialize_session_manifest(session, nct_config.DEFAULT_CONFIG, manifest_path)
            store = capture.CaptureStore(session, manifest_path)
            opener = SimpleNamespace(open=mock.Mock(return_value=FakeResponse()))
            with mock.patch.object(capture.urllib_request, "build_opener", return_value=opener):
                with self.assertRaisesRegex(RuntimeError, "valid SHCC H.Cache.bin"):
                    store._fetch_official_h_cache_once("E")
            self.assertFalse(
                (session / "OpenWF" / "Content" / "0" / "H.Cache.bin!E_---------------------w").exists()
            )
            self.assertFalse((session / "OpenWF" / "Content" / "0" / "UNMANAGED").exists())

    def test_inconsistent_b_cache_manifest_type_removes_generated_unmanaged(self) -> None:
        class FakeResponse(io.BytesIO):
            status = 200

            def __init__(self, data: bytes):
                super().__init__(data)
                self.headers = {"content-length": str(len(data))}

            def getcode(self):
                return self.status

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                self.close()
                return False

        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp) / "session"
            session.mkdir()
            manifest_path = self.manifest_path_for(session)
            capture.initialize_session_manifest(session, nct_config.DEFAULT_CONFIG, manifest_path)
            store = capture.CaptureStore(session, manifest_path)
            official = make_shcc_container(b"official-h-cache")
            opener = SimpleNamespace(open=mock.Mock(return_value=FakeResponse(official)))
            output = io.StringIO()

            with (
                mock.patch.object(capture.urllib_request, "build_opener", return_value=opener),
                contextlib.redirect_stdout(output),
            ):
                store.maybe_fetch_official_h_cache("/0/B.Cache.Windows_zh.bin!E_hash")
                assert store._h_cache_fetch_thread is not None
                store._h_cache_fetch_thread.join(timeout=1)
                self.assertFalse(store._h_cache_fetch_thread.is_alive())
                unmanaged = session / "OpenWF" / "Content" / "0" / "UNMANAGED"
                self.assertTrue(unmanaged.exists())
                store.maybe_fetch_official_h_cache("/0/B.Cache.WindowsDx12.bin!F_hash")

            self.assertFalse(unmanaged.exists())
            manifest = common.read_json_object(manifest_path)
            self.assertTrue(manifest["update_transition_detected"])
            self.assertEqual(manifest["capture_errors"], 0)
            self.assertNotIn("0/UNMANAGED", manifest["files"])
            self.assertIn("0/H.Cache.bin!E_---------------------w", manifest["files"])
            self.assertTrue(store.capture_disabled)
            self.assertTrue(store.drain_requested.is_set())
            self.assertIn(
                "WARNING: B.Cache manifest type changed during the same capture (E -> F).",
                output.getvalue(),
            )
            self.assertIn(
                "ERROR: Multiple update states were detected. Ninja Capture Tool is stopping this session; "
                "start a new session for the current update.",
                output.getvalue(),
            )

    def test_h_cache_manifest_type_is_derived_from_h_cache_filename(self) -> None:
        self.assertEqual(capture.h_cache_manifest_type("/0/H.Cache.bin!D_---------------------w"), "D")
        self.assertEqual(capture.h_cache_manifest_type("/0/H.Cache.bin!E_---------------------w"), "E")
        self.assertIsNone(capture.h_cache_manifest_type("/0/B.Cache.Windows.bin!E_hash"))

    def test_h_cache_captured_after_b_cache_uses_shcc_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp) / "session"
            session.mkdir()
            manifest_path = self.manifest_path_for(session)
            capture.initialize_session_manifest(session, nct_config.DEFAULT_CONFIG, manifest_path)
            store = capture.CaptureStore(session, manifest_path)
            store._b_cache_manifests["b.cache.windows_zh.bin"] = (
                "B.Cache.Windows_zh.bin", "E", "hash"
            )
            store._h_cache_manifest_type = "E"
            filename = "H.Cache.bin!E_---------------------w"
            h_cache = make_shcc_container(b"captured-after-b-cache")
            writer = store.begin(f"https://content.warframe.com/0/{filename}", 200, len(h_cache))
            writer.feed(h_cache)
            writer.feed(b"")

            manifest = common.read_json_object(manifest_path)
            record = manifest["files"][f"0/{filename}"]
            self.assertTrue(record["h_cache_validated"])
            self.assertEqual(record["h_cache_validation_method"], "shcc_container_crc32c")
            self.assertEqual(manifest["h_cache_validation_errors"], 0)
            self.assertTrue((session / "OpenWF" / "Content" / "0" / "UNMANAGED").exists())

    def test_h_cache_unmanaged_gate_cannot_race_same_type_b_cache_transition(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp) / "session"
            session.mkdir()
            manifest_path = self.manifest_path_for(session)
            capture.initialize_session_manifest(session, nct_config.DEFAULT_CONFIG, manifest_path)
            store = capture.CaptureStore(session, manifest_path)
            filename = "H.Cache.bin!E_---------------------w"
            h_cache = make_shcc_container(b"race")
            writer = store.begin(f"https://content.warframe.com/0/{filename}", 200, len(h_cache))
            writer.feed(h_cache)
            writer.feed(b"")
            store._b_cache_manifests["b.cache.windows.bin"] = (
                "B.Cache.Windows.bin", "E", "oldhash"
            )
            store._h_cache_manifest_type = "E"

            validation_started = threading.Event()
            continue_validation = threading.Event()

            def validate(_filename: str) -> bool:
                validation_started.set()
                self.assertTrue(continue_validation.wait(2))
                return store._publish_validated_unmanaged("E")

            with mock.patch.object(store, "_validate_h_cache_for_unmanaged", side_effect=validate):
                thread = threading.Thread(
                    target=store._fetch_official_h_cache_once,
                    args=("E",),
                )
                thread.start()
                self.assertTrue(validation_started.wait(2))
                store.maybe_fetch_official_h_cache("/0/B.Cache.Windows.bin!E_newhash")
                continue_validation.set()
                thread.join(2)
                self.assertFalse(thread.is_alive())

            self.assertTrue(store.drain_requested.is_set())
            self.assertTrue(store.capture_disabled)
            self.assertFalse((session / "OpenWF" / "Content" / "0" / "UNMANAGED").exists())
            manifest = common.read_json_object(manifest_path)
            self.assertTrue(manifest["update_transition_detected"])
            self.assertNotIn("0/UNMANAGED", manifest["files"])

    def test_h_cache_validation_does_not_require_oodle_runtime_files(self) -> None:
        self.assertFalse(hasattr(capture, "find_running_warframe_oodle_dll"))
        self.assertFalse(hasattr(capture, "_OodleHCacheDecoder"))

    def test_crc32c_matches_standard_known_vector(self) -> None:
        self.assertEqual(capture.crc32c(b"123456789"), 0xE3069283)

    def test_h_cache_shcc_validation_is_container_strict_but_codec_agnostic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "H.Cache.bin!E_---------------------w"
            valid = make_shcc_container(b"opaque-compressed-payload", chunk_type=0x7F)
            path.write_bytes(valid)
            self.assertTrue(capture.CaptureStore._h_cache_file_has_sane_structure(path))

            cases: dict[str, bytes] = {}

            bad_header = bytearray(valid)
            bad_header[4] ^= 1
            bad_header[-4:] = struct.pack("<I", capture.crc32c(bytes(bad_header[:-4])))
            cases["header"] = bytes(bad_header)

            bad_size = bytearray(valid)
            compressed_size = struct.unpack_from("<I", bad_size, 13)[0]
            struct.pack_into("<I", bad_size, 13, compressed_size + 1)
            bad_size[-4:] = struct.pack("<I", capture.crc32c(bytes(bad_size[:-4])))
            cases["declared compressed size"] = bytes(bad_size)

            bad_trailer = bytearray(valid)
            bad_trailer[-5] ^= 1
            bad_trailer[-4:] = struct.pack("<I", capture.crc32c(bytes(bad_trailer[:-4])))
            cases["trailer"] = bytes(bad_trailer)

            bad_crc = bytearray(valid)
            bad_crc[-1] ^= 1
            cases["crc32c"] = bytes(bad_crc)

            for label, value in cases.items():
                with self.subTest(label=label):
                    path.write_bytes(value)
                    self.assertFalse(capture.CaptureStore._h_cache_file_has_sane_structure(path))

    def test_generated_unmanaged_does_not_claim_or_remove_preexisting_duplicate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp) / "session"
            session.mkdir()
            manifest_path = self.manifest_path_for(session)
            capture.initialize_session_manifest(session, nct_config.DEFAULT_CONFIG, manifest_path)
            store = capture.CaptureStore(session, manifest_path)
            unmanaged = session / "OpenWF" / "Content" / "0" / "UNMANAGED"
            unmanaged.parent.mkdir(parents=True)
            unmanaged.write_bytes(b"")
            store._b_cache_manifests["b.cache.windows_zh.bin"] = (
                "B.Cache.Windows_zh.bin",
                "E",
                "hash",
            )
            store._h_cache_manifest_type = "E"

            with contextlib.redirect_stdout(io.StringIO()):
                self.assertTrue(store._publish_validated_unmanaged("E"))

            manifest = common.read_json_object(manifest_path)
            record = manifest["files"]["0/UNMANAGED"]
            self.assertNotEqual(record.get("source"), "generated")
            self.assertNotIn("h_cache_manifest_type", record)

            store._remove_generated_unmanaged()
            self.assertTrue(unmanaged.is_file())
            self.assertIn("0/UNMANAGED", common.read_json_object(manifest_path)["files"])

    def test_h_cache_fetch_retries_once_after_transient_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp) / "session"
            session.mkdir()
            manifest_path = self.manifest_path_for(session)
            capture.initialize_session_manifest(session, nct_config.DEFAULT_CONFIG, manifest_path)
            store = capture.CaptureStore(session, manifest_path)
            with (
                mock.patch.object(
                    store,
                    "_fetch_official_h_cache_once",
                    side_effect=[OSError("temporary failure"), None],
                ) as fetch_once,
                mock.patch.object(store.drain_requested, "wait", return_value=False) as wait,
                mock.patch.object(store, "record_capture_error") as record_error,
            ):
                store._fetch_official_h_cache("E")
            self.assertEqual(fetch_once.call_count, 2)
            self.assertEqual(fetch_once.call_args_list, [mock.call("E"), mock.call("E")])
            wait.assert_called_once_with(1.0)
            record_error.assert_not_called()

    def test_h_cache_fetch_does_not_retry_when_drain_starts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp) / "session"
            session.mkdir()
            manifest_path = self.manifest_path_for(session)
            capture.initialize_session_manifest(session, nct_config.DEFAULT_CONFIG, manifest_path)
            store = capture.CaptureStore(session, manifest_path)
            with (
                mock.patch.object(
                    store,
                    "_fetch_official_h_cache_once",
                    side_effect=OSError("temporary failure"),
                ) as fetch_once,
                mock.patch.object(store.drain_requested, "wait", return_value=True) as wait,
                mock.patch.object(store, "record_capture_error") as record_error,
            ):
                store._fetch_official_h_cache("E")
            fetch_once.assert_called_once_with("E")
            wait.assert_called_once_with(1.0)
            record_error.assert_called_once()

    def test_manual_h_cache_fetch_rejects_off_host_redirect(self) -> None:
        handler = capture.ManualFetchRedirectHandler()
        request = capture.urllib_request.Request(
            "https://origin.warframe.com/origin/00000000/0/H.Cache.bin!E_---------------------w"
        )
        with self.assertRaisesRegex(RuntimeError, "refused redirect"):
            handler.redirect_request(
                request,
                None,
                302,
                "Found",
                {},
                "https://example.com/H.Cache.bin",
            )

    def test_manual_h_cache_fetch_allows_expected_https_redirect_hosts(self) -> None:
        handler = capture.ManualFetchRedirectHandler()
        request = capture.urllib_request.Request(
            "https://origin.warframe.com/origin/00000000/0/H.Cache.bin!E_---------------------w"
        )
        redirected = handler.redirect_request(
            request,
            None,
            302,
            "Found",
            {},
            "https://content.warframe.com/0/H.Cache.bin!E_---------------------w",
        )
        self.assertEqual(
            redirected.full_url,
            "https://content.warframe.com/0/H.Cache.bin!E_---------------------w",
        )

    def test_manual_h_cache_url_rejects_credentials_and_nonstandard_https_port(self) -> None:
        self.assertFalse(
            capture.manual_h_cache_url_is_allowed(
                "https://user:password@origin.warframe.com/0/H.Cache.bin!E_---------------------w"
            )
        )
        self.assertFalse(
            capture.manual_h_cache_url_is_allowed(
                "https://origin.warframe.com:444/0/H.Cache.bin!E_---------------------w"
            )
        )
        self.assertTrue(
            capture.manual_h_cache_url_is_allowed(
                "https://origin.warframe.com:443/0/H.Cache.bin!E_---------------------w"
            )
        )

    def test_manual_h_cache_fetch_rejects_oversized_content_length(self) -> None:
        class FakeResponse(io.BytesIO):
            status = 200

            def __init__(self):
                super().__init__(b"SHCCpayload")
                self.headers = {"content-length": str(capture.H_CACHE_MAX_RESPONSE_BYTES + 1)}

            def getcode(self):
                return self.status

            def geturl(self):
                return "https://origin.warframe.com/origin/00000000/0/H.Cache.bin!E_---------------------w"

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                self.close()
                return False

        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp) / "session"
            session.mkdir()
            manifest_path = self.manifest_path_for(session)
            capture.initialize_session_manifest(session, nct_config.DEFAULT_CONFIG, manifest_path)
            store = capture.CaptureStore(session, manifest_path)
            opener = SimpleNamespace(open=mock.Mock(return_value=FakeResponse()))
            with mock.patch.object(capture.urllib_request, "build_opener", return_value=opener):
                with self.assertRaisesRegex(RuntimeError, "unexpectedly large"):
                    store._fetch_official_h_cache_once("E")
            self.assertFalse(
                (session / "OpenWF" / "Content" / "0" / "H.Cache.bin!E_---------------------w").exists()
            )

    def test_manual_h_cache_fetch_rejects_chunked_response_past_size_limit(self) -> None:
        class FakeResponse(io.BytesIO):
            status = 200

            def __init__(self, data: bytes):
                super().__init__(data)
                self.headers = {}

            def getcode(self):
                return self.status

            def geturl(self):
                return "https://origin.warframe.com/origin/00000000/0/H.Cache.bin!E_---------------------w"

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                self.close()
                return False

        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp) / "session"
            session.mkdir()
            manifest_path = self.manifest_path_for(session)
            capture.initialize_session_manifest(session, nct_config.DEFAULT_CONFIG, manifest_path)
            store = capture.CaptureStore(session, manifest_path)
            opener = SimpleNamespace(open=mock.Mock(return_value=FakeResponse(b"SHCC123456789")))
            with (
                mock.patch.object(capture.urllib_request, "build_opener", return_value=opener),
                mock.patch.object(capture, "H_CACHE_MAX_RESPONSE_BYTES", 8),
            ):
                with self.assertRaisesRegex(RuntimeError, "safe size limit"):
                    store._fetch_official_h_cache_once("E")
            self.assertFalse(
                (session / "OpenWF" / "Content" / "0" / "H.Cache.bin!E_---------------------w").exists()
            )

    def test_capture_store_uses_output_temp_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = root / "session"
            session.mkdir()
            manifest_path = root / "session_session.json"
            capture.initialize_session_manifest(
                session,
                dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None),
                manifest_path,
            )
            store = capture.CaptureStore(session, manifest_path)
            self.assertEqual(store.temp_root, (root / ".temp").resolve())
            self.assertTrue((root / ".temp" / ".nct-owned").is_file())
            self.assertFalse((session / ".temp").exists())
            common.remove_capture_temp_root(store.temp_root)

    def test_restart_target_accepts_nested_relative_path_and_creates_parents(self) -> None:
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
            pending = session._prepare_rotation_target("Older Builds/U43.5.1")
            try:
                target = Path(pending["session_root"])
                self.assertEqual(target, (root / "Older Builds" / "U43.5.1").resolve())
                self.assertTrue(target.is_dir())
                self.assertTrue(Path(pending["manifest_path"]).is_file())
            finally:
                session._discard_rotation_target(pending)

    def test_restart_target_rejects_trailing_space_without_sanitizing(self) -> None:
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
            with self.assertRaisesRegex(RuntimeError, "ending in a space or period"):
                session._prepare_rotation_target("U43.5.1 ")
            self.assertFalse((root / "U43.5.1").exists())

    def test_restart_target_reports_low_space_for_the_selected_parent(self) -> None:
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
            session.restart_prompt_state = "path"
            session.restart_prompt_text = "new"
            session.suppress_console_output = True
            session.restart_prompt_previous_suppression = False
            with session.worker_activity_lock:
                session.worker_active_captures = 2
            with (
                mock.patch.object(common, "prepare_output_directory", return_value=512 * 1024 * 1024),
                mock.patch.object(session, "_send_rotation_request"),
                mock.patch.object(session, "log") as log,
                mock.patch.object(session, "_prompt_write"),
            ):
                session._finish_restart_path_entry()
                session._begin_restart_prompt()
            messages = [call.args[0] for call in log.call_args_list]
            self.assertTrue(any("new session's output drive" in message for message in messages))
            self.assertTrue(any("Waiting for 2 active captures" in message for message in messages))
            self.assertTrue(any("already been requested" in message for message in messages))
            if session.pending_rotation is not None:
                session._discard_rotation_target(session.pending_rotation)

    def test_restart_hotkey_consumes_extended_key_sequence_and_ctrl_c_during_confirmation(self) -> None:
        class FakeMsvcrt:
            def __init__(self, characters: list[str]):
                self.characters = characters

            def kbhit(self) -> bool:
                return bool(self.characters)

            def getwch(self) -> str:
                return self.characters.pop(0)

        options = dict(nct_config.DEFAULT_CONFIG)
        session = nct.CaptureSession(options)
        session.restart_prompt_state = "path"
        fake = FakeMsvcrt(["\xe0", "K"])
        with (
            mock.patch.object(nct_runtime.sys, "platform", "win32"),
            mock.patch.object(nct.sys, "stdin", SimpleNamespace(isatty=lambda: True)),
            mock.patch.dict(sys.modules, {"msvcrt": fake}),
        ):
            session._poll_restart_hotkey()
        self.assertEqual(session.restart_prompt_text, "")

        session.restart_prompt_state = "confirm"
        fake = FakeMsvcrt(["\x03"])
        with (
            mock.patch.object(nct_runtime.sys, "platform", "win32"),
            mock.patch.object(nct.sys, "stdin", SimpleNamespace(isatty=lambda: True)),
            mock.patch.dict(sys.modules, {"msvcrt": fake}),
            self.assertRaises(KeyboardInterrupt),
        ):
            session._poll_restart_hotkey()

    def test_exact_output_path_accepts_existing_empty_directory_and_rejects_nonempty_reuse(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested" / "U43.5.4"
            path.parent.mkdir()
            session = common.create_exact_session_directory(path)
            self.assertEqual(session, path)
            self.assertFalse((session / "OpenWF").exists())
            self.assertEqual(common.create_exact_session_directory(path), path)
            (path / "existing.bin").write_bytes(b"old")
            with self.assertRaisesRegex(RuntimeError, "not empty"):
                common.create_exact_session_directory(path)

    def test_output_option_accepts_an_exact_nested_path(self) -> None:
        parser = nct_config.build_argument_parser()
        self.assertEqual(parser.parse_args(["--output", "captures/U43.5.4"]).output, "captures/U43.5.4")

    def test_exact_output_creates_missing_parent_directories(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "new" / "nested" / "U43.5.1"
            created = common.create_exact_session_directory(path)
            self.assertEqual(created, path)
            self.assertTrue(path.is_dir())

    def test_unavailable_windows_root_is_rejected_before_directory_creation(self) -> None:
        fake = types.SimpleNamespace(anchor="A:\\")
        with mock.patch.object(common.sys, "platform", "win32"):
            with self.assertRaisesRegex(RuntimeError, "does not exist or is unavailable"):
                common.validate_existing_session_root(fake, "Session path")

    def test_unrelated_existing_exact_output_is_rejected_without_root_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            requested = root / "U43.5.4"
            (requested / ".temp").mkdir(parents=True)
            important = requested / ".temp" / "important.txt"
            important.write_text("keep", encoding="utf-8")
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=requested)
            session = nct.CaptureSession(options)
            with (
                mock.patch.object(windows_proxy, "restore_stale_recovery", return_value=None),
                mock.patch.object(common, "prepare_runtime_state_directory"),
                mock.patch.object(common, "prepare_output_directory", return_value=2 * 1024 * 1024 * 1024),
                mock.patch.object(common, "recover_stale_sessions") as recover,
            ):
                with self.assertRaisesRegex(RuntimeError, "already exists"):
                    session.start()
            recover.assert_not_called()
            self.assertEqual(important.read_text(encoding="utf-8"), "keep")

    def test_empty_aborted_exact_output_is_recovered_and_reused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            requested = root / "U43.5.4"
            requested.mkdir()
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=requested)
            old_log_path, old_manifest_path = self.make_sidecar_session_metadata(requested, options)
            manifest = common.read_json_object(old_manifest_path)
            manifest["status"] = "aborted"
            manifest["finished_at"] = common.current_timestamp()
            common.atomic_write_json(old_manifest_path, manifest)
            old_log_path.write_text("old session\n", encoding="utf-8")
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
            self.assertFalse(old_log_path.exists())
            self.assertFalse(old_manifest_path.exists())
            assert session.manifest_path is not None and session.log_path is not None
            self.assertEqual(common.read_json_object(session.manifest_path)["status"], "starting")
            self.assertEqual(session.manifest_path.parent, root)
            self.assertEqual(session.log_path.parent, root)
            self.assertRegex(session.log_path.name, r"^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}(?:_\d+)?_capture\.log$")
            self.assertRegex(session.manifest_path.name, r"^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}(?:_\d+)?_session\.json$")
            self.assertEqual(common.read_json_object(session.manifest_path)["capture_directory"], "U43.5.4")
            self.assertFalse((requested / "session.json").exists())
            self.assertFalse((requested / "capture.log").exists())

    def test_unfinished_exact_output_is_preserved_and_not_reused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            requested = root / "U43.5.4"
            requested.mkdir()
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=requested)
            log_path, manifest_path = self.make_sidecar_session_metadata(requested, options)
            log_path.write_text("crash diagnostics\n", encoding="utf-8")
            session = nct.CaptureSession(options)
            with (
                mock.patch.object(windows_proxy, "restore_stale_recovery", return_value=None),
                mock.patch.object(common, "prepare_runtime_state_directory"),
                mock.patch.object(common, "prepare_output_directory", return_value=2 * 1024 * 1024 * 1024),
            ):
                with self.assertRaisesRegex(RuntimeError, "already exists"):
                    session.start()
            self.assertTrue(requested.is_dir())
            self.assertEqual(log_path.read_text(encoding="utf-8"), "crash diagnostics\n")
            recovered = common.read_json_object(manifest_path)
            self.assertEqual(recovered["status"], "interrupted")
            self.assertIsNotNone(recovered["finished_at"])

    def test_exact_output_does_not_recover_unrelated_sibling_directories(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            requested = root / "U43.5.4"
            options = dict(nct_config.DEFAULT_CONFIG, capture_mode="system-proxy", output_root=root, output_path=requested)
            session = nct.CaptureSession(options)
            with (
                mock.patch.object(windows_proxy, "restore_stale_recovery", return_value=None),
                mock.patch.object(common, "prepare_runtime_state_directory"),
                mock.patch.object(nct_runtime, "ensure_mitmproxy_ca_trusted", return_value=False),
                mock.patch.object(common, "prepare_output_directory", return_value=2 * 1024 * 1024 * 1024),
                mock.patch.object(common, "recover_stale_sessions") as recover,
                mock.patch.object(windows_proxy, "ensure_port_available"),
                mock.patch.object(windows_proxy, "get_proxy_settings", return_value={}),
                mock.patch.object(windows_proxy, "resolve_upstream_proxy", return_value=(None, None)),
                mock.patch.object(nct_session, "SessionLogger"),
                mock.patch.object(session, "_start_worker"),
                mock.patch.object(session, "_wait_for_worker_ready"),
                mock.patch.object(windows_proxy, "activate_local_proxy", return_value={}),
            ):
                session.start()
            recover.assert_not_called()
            self.assertEqual(session.session_root, requested)

    def test_live_saving_progress_truncates_long_path_to_terminal_width(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            logger = nct_session.SessionLogger(Path(tmp) / "capture.log")
            stdout = io.StringIO()
            message = (
                "[Saving] 25.0 MiB / 100.0 MiB (25.0%) | 12.0 MiB/s | "
                "/0/very/long/launcher/path/that/would/wrap/really-long-file-name.bin"
            )
            with (
                mock.patch.object(nct_session.SessionLogger, "_interactive_console", return_value=True),
                mock.patch.object(nct.shutil, "get_terminal_size", return_value=os.terminal_size((90, 24))),
                mock.patch.object(common, "console_supports_color", return_value=False),
                contextlib.redirect_stdout(stdout),
            ):
                logger.show_progress(message)
            logger.close()
            rendered = stdout.getvalue().split("\r", 1)[1].rstrip()
            self.assertLessEqual(len(rendered), 89)
            self.assertIn("...", rendered)
            self.assertTrue(rendered.endswith("really-long-file-name.bin"))

    def test_transient_progress_message_formats_known_and_unknown_lengths_with_speed(self) -> None:
        self.assertEqual(
            nct_session._progress_message(
                "Saving", 5 * 1024 * 1024 // 2, 5 * 1024 * 1024, "/known.bin", 3 * 1024 * 1024
            ),
            "[Saving] 2.5 MiB / 5.0 MiB (50.0%) | 3.0 MiB/s | /known.bin",
        )
        self.assertEqual(
            nct_session._progress_message(
                "Extracting", 3 * 1024 * 1024, None, "Warframe.x64.exe", 2 * 1024 * 1024
            ),
            "[Extracting] 3.0 MiB | 2.0 MiB/s | Warframe.x64.exe",
        )

    def test_custom_single_process_uses_singular_active_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            options = dict(
                nct_config.DEFAULT_CONFIG,
                processes=["CustomGame.exe"],
                output_root=root,
                output_path=root / "single-process",
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
            self.assertIn(
                "Capture is active. Start the selected process to capture downloaded assets.\nPress Ctrl+C when finished or Ctrl+R to start a new session.",
                stdout.getvalue(),
            )
            assert session.logger is not None
            session.logger.close()

    def test_custom_multiple_processes_use_plural_active_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            options = dict(
                nct_config.DEFAULT_CONFIG,
                processes=["First.exe", "Second.exe"],
                output_root=root,
                output_path=root / "multiple-processes",
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
            self.assertIn(
                "Capture is active. Start one of the selected processes to capture downloaded assets.\nPress Ctrl+C when finished or Ctrl+R to start a new session.",
                stdout.getvalue(),
            )
            assert session.logger is not None
            session.logger.close()

    def test_frozen_capture_smoke_exercises_capture_writer(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(capture.run_frozen_capture_smoke_test(), 0)

    def test_stale_capture_temp_cleanup_refuses_unowned_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            temporary = root / ".temp"
            temporary.mkdir()
            important = temporary / "important.txt"
            important.write_text("keep", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "not a Ninja Capture Tool workspace"):
                common.clear_stale_capture_temp(root)
            self.assertEqual(important.read_text(encoding="utf-8"), "keep")

    def test_nested_capture_log_counts_as_payload_during_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = root / "old"
            (session / "OpenWF" / "Content").mkdir(parents=True)
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None)
            _, manifest_path = self.make_sidecar_session_metadata(session, options)
            manifest = common.read_json_object(manifest_path)
            manifest["status"] = "running"
            common.atomic_write_json(manifest_path, manifest)
            payload = session / "OpenWF" / "Content" / "capture.log"
            payload.write_bytes(b"real payload")
            interrupted, warnings = common.recover_stale_sessions(root)
            self.assertEqual((interrupted, warnings), (1, []))
            self.assertEqual(payload.read_bytes(), b"real payload")

    def test_stale_capture_temp_cleanup_removes_owned_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            temporary = common.prepare_capture_temp_root(root)
            self.assertTrue(temporary.is_dir())
            self.assertFalse(common.clear_stale_capture_temp(root))
            self.assertFalse(temporary.exists())
            self.assertFalse(common.clear_stale_capture_temp(root))

    def test_stale_capture_temp_cleanup_removes_partial_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            temporary = common.prepare_capture_temp_root(root)
            partial = temporary / "OpenWF" / "Content" / "capture.part"
            partial.parent.mkdir(parents=True)
            partial.write_bytes(b"partial")
            self.assertTrue(common.clear_stale_capture_temp(root))
            self.assertFalse(temporary.exists())

    def test_stream_capture_writes_file_and_sha256_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            store = capture.CaptureStore(session, self.manifest_path_for(session))
            writer = store.begin("https://content.warframe.com/a/b.bin", 200, expected_size=7)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(writer.feed(b"pay"), b"pay")
                self.assertEqual(writer.feed(b"load"), b"load")
                writer.feed(b"")
            saved = session / "OpenWF" / "Content" / "a" / "b.bin"
            self.assertEqual(saved.read_bytes(), b"payload")
            manifest = json.loads(self.manifest_path_for(session).read_text(encoding="utf-8"))
            record = manifest["files"]["a/b.bin"]
            self.assertEqual(record["size"], 7)
            self.assertEqual(record["sha256"], hashlib.sha256(b"payload").hexdigest())
            self.assertEqual(manifest["captured_files"], 1)
            self.assertEqual(manifest["captured_bytes"], 7)

    def test_saving_progress_speed_uses_a_short_rolling_window(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            store = capture.CaptureStore(session, self.manifest_path_for(session), worker_protocol_enabled=True)
            output = io.StringIO()
            with (
                mock.patch.object(capture.time, "monotonic", side_effect=[100.0, 100.6, 100.9, 102.2]),
                contextlib.redirect_stdout(output),
            ):
                writer = store.begin("https://content.warframe.com/a.bin", 200, expected_size=200)
                writer.feed(b"a" * 100)
                writer.feed(b"b")
                writer.feed(b"c")
                writer.abort()

            payloads = [
                message for message in worker_messages(output.getvalue())
                if message.get("type") == "progress" and message.get("action") == "saving"
            ]
            # The second reading averages the initial burst instead of reporting
            # only the 1 byte received during the most recent 0.3 seconds. The
            # third reading has aged that burst out of the 1.5-second window.
            self.assertEqual([payload["speed_bps"] for payload in payloads], [166, 112, 1])

    def test_saving_progress_heartbeat_drops_stalled_speed_to_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            store = capture.CaptureStore(session, self.manifest_path_for(session), worker_protocol_enabled=True)
            output = io.StringIO()
            with (
                mock.patch.object(capture.time, "monotonic", side_effect=[100.0, 100.6, 102.2]),
                mock.patch.object(store._saving_progress_stop, "wait", side_effect=[False, True]),
                contextlib.redirect_stdout(output),
            ):
                writer = store.begin("https://content.warframe.com/a.bin", 200, expected_size=200)
                writer.feed(b"a" * 100)
                store._saving_progress_loop()
                writer.abort()

            payloads = [
                message for message in worker_messages(output.getvalue())
                if message.get("type") == "progress" and message.get("action") == "saving"
            ]
            self.assertEqual([payload["speed_bps"] for payload in payloads], [166, 0])

    def test_concurrent_saving_progress_stays_on_foreground_and_hands_off_immediately(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            store = capture.CaptureStore(session, self.manifest_path_for(session), worker_protocol_enabled=True)
            output = io.StringIO()
            with (
                mock.patch.object(
                    capture.time,
                    "monotonic",
                    side_effect=[100.0, 100.1, 100.6, 100.7, 100.9, 101.0, 101.1],
                ),
                contextlib.redirect_stdout(output),
            ):
                first = store.begin("https://content.warframe.com/a.bin", 200, expected_size=8)
                second = store.begin("https://content.warframe.com/b.bin", 200, expected_size=8)
                first.feed(b"aa")
                second.feed(b"bb")
                first.feed(b"cc")
                first.abort()
                store.record_incomplete("/a.bin", 8, 4, "test abort")
                # No additional data is fed to the second writer: its progress must
                # be emitted by the foreground handoff itself and restored after the
                # permanent error line clears the transient console row.
                second.abort()

            payloads = [
                message for message in worker_messages(output.getvalue())
                if message.get("type") == "progress" and message.get("action") == "saving"
            ]
            self.assertEqual([payload["path"] for payload in payloads], ["/a.bin", "/a.bin", "/b.bin", "/b.bin"])
            lines = output.getvalue().splitlines()
            error_index = next(index for index, line in enumerate(lines) if line.startswith("ERROR: Incomplete response"))
            self.assertEqual(common.parse_worker_message(lines[error_index + 1]).get("action"), "saving")

    def test_known_size_capture_stops_local_write_before_exceeding_content_length(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            store = capture.CaptureStore(session, self.manifest_path_for(session))
            writer = store.begin("https://content.warframe.com/a.bin", 200, expected_size=3)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(writer.feed(b"abcd"), b"abcd")
                self.assertEqual(writer.feed(b"more"), b"more")
            self.assertTrue(writer.failed)
            self.assertFalse((session / "OpenWF" / "Content" / "a.bin").exists())
            self.assertFalse(writer.temporary.exists())
            self.assertEqual(store.reserved_bytes, 0)
            manifest = common.read_json_object(self.manifest_path_for(session))
            self.assertEqual(manifest["incomplete_responses"], 1)
            self.assertEqual(manifest["captured_files"], 0)

    def test_query_string_is_not_logged_or_stored_in_manifest_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp) / "session"
            session.mkdir()
            capture.initialize_session_manifest(
                session,
                dict(nct_config.DEFAULT_CONFIG, output_root=Path(tmp), output_path=None),
                self.manifest_path_for(session),
            )
            store = capture.CaptureStore(session, self.manifest_path_for(session))
            writer = store.begin(
                "https://content.warframe.com/file.bin?token=secret-value", 200, expected_size=3
            )
            writer.feed(b"abc")
            writer.feed(b"")
            manifest = common.read_json_object(self.manifest_path_for(session))
            record = manifest["files"]["file.bin"]
            self.assertEqual(record["path"], "/file.bin")
            self.assertNotIn("secret-value", json.dumps(manifest))
            self.assertNotIn("query_sha256", record)

    def test_saved_log_places_size_before_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            writer = capture.CaptureStore(session, self.manifest_path_for(session)).begin("https://content.warframe.com/a.bin", 200, 3)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                writer.feed(b"abc")
                writer.feed(b"")
            text = output.getvalue()
            self.assertIn("[Saved] 3 B | 200 | /a.bin", text)
            self.assertNotIn("Stored as:", text)

    def test_manual_h_cache_failure_uses_ninja_capture_tool_source_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            store = capture.CaptureStore(
                session,
                self.manifest_path_for(session),
                worker_protocol_enabled=True,
            )
            output = io.StringIO()
            with (
                mock.patch.object(
                    store,
                    "_fetch_official_h_cache_once",
                    side_effect=RuntimeError("fetch failed"),
                ),
                mock.patch.object(store.drain_requested, "wait", return_value=False),
                contextlib.redirect_stdout(output),
            ):
                store._fetch_official_h_cache("E")

            result = next(
                message
                for message in worker_messages(output.getvalue())
                if message.get("type") == "output" and "Capture failed for /0/H.Cache.bin" in str(message.get("log"))
            )
            self.assertNotIn("Source:", str(result["console"]))
            self.assertTrue(str(result["log"]).endswith("| Source: Fetched by Ninja Capture Tool"))

    def test_nct_owned_capture_results_use_source_provenance_in_log_variant(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            store = capture.CaptureStore(
                session,
                self.manifest_path_for(session),
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
            self.assertNotIn("Source:", h_cache_result["console"])
            self.assertTrue(str(h_cache_result["log"]).endswith("| Source: Fetched by Ninja Capture Tool"))
            self.assertNotIn("Source:", unmanaged_result["console"])
            self.assertTrue(str(unmanaged_result["log"]).endswith("| Source: Generated by Ninja Capture Tool"))

    def test_windows_full_path_guard_rejects_nt_path_limit(self) -> None:
        path = Path("C:/") / ("a/" * 17000)
        with mock.patch.object(common.sys, "platform", "win32"):
            with self.assertRaisesRegex(ValueError, "path-length limit"):
                common.validate_windows_full_path(path, "Capture output path")

    def test_root_path_filter_matches_lotus_and_tools_but_not_nested_paths(self) -> None:
        self.assertTrue(capture.is_filtered_root_url("https://content.warframe.com/Lotus/Language/MOTD_en.rtf.lzma"))
        self.assertTrue(capture.is_filtered_root_url("https://content.warframe.com/Lotus"))
        self.assertFalse(capture.is_filtered_root_url("https://content.warframe.com/0/Lotus/Interface/file.bin"))
        self.assertFalse(capture.is_filtered_root_url("https://content.warframe.com/Cache.Windows/Lotus/file.bin"))
        self.assertTrue(capture.is_filtered_root_url("https://content.warframe.com/Tools/windows/x64/file.bin"))
        self.assertTrue(capture.is_filtered_root_url("https://content.warframe.com/Tools"))
        self.assertFalse(capture.is_filtered_root_url("https://content.warframe.com/0/Tools/file.bin"))
        self.assertFalse(capture.is_filtered_root_url("https://content.warframe.com/Cache.Windows/Tools/file.bin"))

    def test_root_lotus_response_is_logged_and_not_saved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            addon = capture.CaptureAddon(session, self.manifest_path_for(session))
            flow = self.fake_flow(
                200,
                url="https://content.warframe.com/Lotus/Language/MOTD_en.rtf.lzma",
                content_length="1024",
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                addon.responseheaders(flow)
            self.assertIs(flow.response.stream, capture.passthrough_stream)
            self.assertEqual(flow.response.stream(b"unchanged"), b"unchanged")
            self.assertIn("[Filtered] /Lotus/Language/MOTD_en.rtf.lzma", output.getvalue())
            self.assertNotIn("| 200 |", output.getvalue())
            manifest = json.loads(self.manifest_path_for(session).read_text(encoding="utf-8"))
            self.assertEqual(manifest["filtered_root_paths"], 1)

    def test_root_tools_response_is_filtered_and_not_saved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            addon = capture.CaptureAddon(session, self.manifest_path_for(session))
            flow = self.fake_flow(
                200,
                url="https://content.warframe.com/Tools/windows/x64/discord_game_sdk.dll.hash.lzma",
                content_length="2048",
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                addon.responseheaders(flow)
            self.assertIs(flow.response.stream, capture.passthrough_stream)
            self.assertIn(
                "[Filtered] /Tools/windows/x64/discord_game_sdk.dll.hash.lzma",
                output.getvalue(),
            )
            self.assertNotIn("| 200 |", output.getvalue())
            manifest = json.loads(self.manifest_path_for(session).read_text(encoding="utf-8"))
            self.assertEqual(manifest["filtered_root_paths"], 1)
            self.assertFalse((session / "OpenWF" / "Content" / "Tools").exists())

    def test_warframe_executable_archive_is_extracted_and_md5_verified(self) -> None:
        executable = (b"MZ" + bytes(range(256))) * 512
        expected_md5 = hashlib.md5(executable, usedforsecurity=False).hexdigest().upper()
        compressed = lzma.compress(executable, format=lzma.FORMAT_ALONE)
        name = f"Warframe.x64.exe.{expected_md5}.lzma"
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            writer = capture.CaptureStore(session, self.manifest_path_for(session)).begin(
                f"https://content.warframe.com/{name}", 200, len(compressed)
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                writer.feed(compressed)
                writer.feed(b"")
            self.assertEqual((session / "Warframe.x64.exe").read_bytes(), executable)
            self.assertFalse((session / "OpenWF" / "Content" / name).exists())
            self.assertIn("[Extracted]", output.getvalue())
            self.assertIn("MD5 OK", output.getvalue())
            manifest = json.loads(self.manifest_path_for(session).read_text(encoding="utf-8"))
            extracted = manifest["extracted_executable"]
            self.assertEqual(extracted["md5"], expected_md5.lower())
            self.assertNotIn("sha256", extracted)
            self.assertTrue(extracted["source_removed"])
            self.assertTrue(manifest["files"][name]["removed_after_extract"])
            self.assertEqual(manifest["extraction_errors"], 0)

    def test_repeated_executable_archive_stays_removed_after_successful_extraction(self) -> None:
        executable = b"MZ" + b"repeat executable payload" * 128
        expected_md5 = hashlib.md5(executable, usedforsecurity=False).hexdigest().upper()
        compressed = lzma.compress(executable, format=lzma.FORMAT_ALONE)
        name = f"Warframe.x64.exe.{expected_md5}.lzma"
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            store = capture.CaptureStore(session, self.manifest_path_for(session))
            first = store.begin(f"https://content.warframe.com/{name}", 200, len(compressed))
            with contextlib.redirect_stdout(io.StringIO()):
                first.feed(compressed)
                first.feed(b"")

            archive = session / "OpenWF" / "Content" / name
            self.assertFalse(archive.exists())
            output = io.StringIO()
            second = store.begin(f"https://content.warframe.com/{name}", 200, len(compressed))
            with contextlib.redirect_stdout(output):
                second.feed(compressed)
                second.feed(b"")

            self.assertFalse(archive.exists())
            self.assertEqual((session / "Warframe.x64.exe").read_bytes(), executable)
            self.assertIn("[Duplicate]", output.getvalue())
            manifest = common.read_json_object(self.manifest_path_for(session))
            self.assertEqual(manifest["duplicates"], 1)
            self.assertTrue(manifest["files"][name]["removed_after_extract"] )

    def test_existing_executable_md5_is_explicitly_nonsecurity(self) -> None:
        executable = b"MZ" + b"existing executable payload" * 64
        expected_md5 = hashlib.md5(executable, usedforsecurity=False).hexdigest().upper()
        name = f"Warframe.x64.exe.{expected_md5}.lzma"
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            (session / "Warframe.x64.exe").write_bytes(executable)
            archive = session / "OpenWF" / "Content" / name
            archive.parent.mkdir(parents=True, exist_ok=True)
            archive.write_bytes(b"")
            store = capture.CaptureStore(session, self.manifest_path_for(session))
            original_md5 = hashlib.md5
            with (
                mock.patch.object(capture.hashlib, "md5", wraps=original_md5) as md5_constructor,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                store._extract_executable_if_needed(Path(name), archive)
            md5_constructor.assert_called_once_with(usedforsecurity=False)
            self.assertEqual(common.read_json_object(self.manifest_path_for(session))["extraction_errors"], 0)

    def test_lzma_alone_declared_size_is_used_only_when_known(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "sample.lzma"
            archive.write_bytes(b"\x5d\x00\x00\x80\x00" + (123456).to_bytes(8, "little"))
            self.assertEqual(capture.CaptureStore._lzma_alone_uncompressed_size(archive), 123456)
            archive.write_bytes(b"\x5d\x00\x00\x80\x00" + b"\xff" * 8)
            self.assertIsNone(capture.CaptureStore._lzma_alone_uncompressed_size(archive))

    def test_duplicate_executable_postprocessing_is_serialized(self) -> None:
        executable = b"MZ" + b"parallel executable payload" * 256
        expected_md5 = hashlib.md5(executable, usedforsecurity=False).hexdigest().upper()
        compressed = lzma.compress(executable, format=lzma.FORMAT_ALONE)
        name = f"Warframe.x64.exe.{expected_md5}.lzma"
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            archive = session / "OpenWF" / "Content" / name
            archive.parent.mkdir(parents=True, exist_ok=True)
            archive.write_bytes(compressed)
            store = capture.CaptureStore(session, self.manifest_path_for(session))
            original_open = capture.lzma.open
            calls = []
            def slow_open(*args, **kwargs):
                calls.append(1)
                time.sleep(0.05)
                return original_open(*args, **kwargs)
            threads = [
                threading.Thread(target=store._extract_executable_if_needed, args=(Path(name), archive))
                for _ in range(2)
            ]
            with mock.patch.object(capture.lzma, "open", side_effect=slow_open), contextlib.redirect_stdout(io.StringIO()):
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join()
            self.assertEqual(len(calls), 1)
            self.assertEqual((session / "Warframe.x64.exe").read_bytes(), executable)
            self.assertEqual(common.read_json_object(self.manifest_path_for(session))["extraction_errors"], 0)

    def test_executable_extraction_waits_for_space_and_resumes(self) -> None:
        DiskUsage = namedtuple("usage", "total used free")
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            payload = b"MZ" + b"x" * 1024
            expected_md5 = hashlib.md5(payload, usedforsecurity=False).hexdigest().upper()
            archive = session / "OpenWF" / "Content" / f"Warframe.x64.exe.{expected_md5}.lzma"
            archive.parent.mkdir(parents=True, exist_ok=True)
            archive.write_bytes(lzma.compress(payload))
            store = capture.CaptureStore(
                session, self.manifest_path_for(session), worker_protocol_enabled=True
            )
            headroom = capture.DISK_SAFETY_HEADROOM_BYTES
            output = io.StringIO()
            with (
                mock.patch.object(
                    capture.shutil,
                    "disk_usage",
                    side_effect=[
                        DiskUsage(headroom + 1, 0, headroom),
                        DiskUsage(headroom + 4096, 0, headroom + 4096),
                    ],
                ),
                mock.patch.object(capture.time, "sleep"),
                contextlib.redirect_stdout(output),
            ):
                store._extract_executable_if_needed(Path(archive.name), archive)
            self.assertFalse(archive.exists())
            self.assertEqual((session / "Warframe.x64.exe").read_bytes(), payload)
            manifest = common.read_json_object(self.manifest_path_for(session))
            self.assertEqual(manifest["extraction_errors"], 0)
            self.assertTrue(any(message.get("type") == "waiting" for message in worker_messages(output.getvalue())))

    def test_executable_extraction_reserves_space_against_concurrent_capture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            payload = b"MZ" + b"x" * (1024 * 1024 + 128)
            expected_md5 = hashlib.md5(payload, usedforsecurity=False).hexdigest().upper()
            archive = session / "OpenWF" / "Content" / f"Warframe.x64.exe.{expected_md5}.lzma"
            archive.parent.mkdir(parents=True, exist_ok=True)
            archive.write_bytes(lzma.compress(payload))
            store = capture.CaptureStore(session, self.manifest_path_for(session))
            original_write_all_with_disk_wait = store.write_all_with_disk_wait
            observed_reserved: list[int] = []

            def assert_reserved(destination, data, path, *, writer=None):
                if not observed_reserved and ".extract.part" in str(getattr(destination, "name", "")):
                    observed_reserved.append(store.reserved_bytes)
                    self.assertGreater(store.reserved_bytes, 0)
                return original_write_all_with_disk_wait(destination, data, path, writer=writer)

            fake_usage = SimpleNamespace(free=capture.DISK_SAFETY_HEADROOM_BYTES + 1024 * 1024)
            with (
                mock.patch.object(capture.shutil, "disk_usage", return_value=fake_usage),
                mock.patch.object(store, "write_all_with_disk_wait", side_effect=assert_reserved),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                store._extract_executable_if_needed(Path(archive.name), archive)

            self.assertTrue(observed_reserved)
            self.assertGreaterEqual(observed_reserved[0], 1024 * 1024)
            self.assertEqual(store.reserved_bytes, 0)
            self.assertEqual((session / "Warframe.x64.exe").read_bytes(), payload)

    def test_unrelated_root_lzma_is_never_extracted(self) -> None:
        payload = b"unrelated compressed payload" * 128
        compressed = lzma.compress(payload, format=lzma.FORMAT_ALONE)
        name = "UnrelatedAsset.0123456789ABCDEF0123456789ABCDEF.lzma"
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            writer = capture.CaptureStore(session, self.manifest_path_for(session)).begin(
                f"https://content.warframe.com/{name}", 200, len(compressed)
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                writer.feed(compressed)
                writer.feed(b"")
            self.assertEqual((session / "OpenWF" / "Content" / name).read_bytes(), compressed)
            self.assertFalse((session / "Warframe.x64.exe").exists())
            self.assertNotIn("[Extracted]", output.getvalue())
            manifest = json.loads(self.manifest_path_for(session).read_text(encoding="utf-8"))
            self.assertEqual(manifest["extraction_errors"], 0)
            self.assertIsNone(manifest["extracted_executable"])

    def test_nested_warframe_executable_lzma_is_never_extracted(self) -> None:
        executable = b"MZ" + b"nested executable payload" * 128
        expected_md5 = hashlib.md5(executable, usedforsecurity=False).hexdigest().upper()
        compressed = lzma.compress(executable, format=lzma.FORMAT_ALONE)
        name = f"Warframe.x64.exe.{expected_md5}.lzma"
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            writer = capture.CaptureStore(session, self.manifest_path_for(session)).begin(
                f"https://content.warframe.com/nested/{name}", 200, len(compressed)
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                writer.feed(compressed)
                writer.feed(b"")
            self.assertEqual((session / "OpenWF" / "Content" / "nested" / name).read_bytes(), compressed)
            self.assertFalse((session / "Warframe.x64.exe").exists())
            self.assertNotIn("[Extracted]", output.getvalue())
            manifest = json.loads(self.manifest_path_for(session).read_text(encoding="utf-8"))
            self.assertEqual(manifest["extraction_errors"], 0)
            self.assertIsNone(manifest["extracted_executable"])

    def test_executable_extraction_survives_short_filesystem_writes(self) -> None:
        payload = (b"Warframe executable payload" * 4096) + b"!"
        expected_md5 = hashlib.md5(payload, usedforsecurity=False).hexdigest()
        archive_name = f"Warframe.x64.exe.{expected_md5}.lzma"

        class ShortWriteFile:
            def __init__(self, file):
                self.file = file
            def __enter__(self):
                return self
            def __exit__(self, *args):
                self.file.close()
            def write(self, data):
                chunk = bytes(data)
                count = max(1, len(chunk) // 2)
                return self.file.write(chunk[:count])
            def close(self):
                self.file.close()
            @property
            def closed(self):
                return self.file.closed

        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp) / "session"
            session.mkdir()
            capture.initialize_session_manifest(
                session,
                dict(nct_config.DEFAULT_CONFIG, output_root=Path(tmp), output_path=None),
                self.manifest_path_for(session),
            )
            store = capture.CaptureStore(session, self.manifest_path_for(session))
            compressed = lzma.compress(payload)
            original_open = Path.open
            def short_extract_open(path, *args, **kwargs):
                file = original_open(path, *args, **kwargs)
                if ".extract.part" in path.name and args and "w" in str(args[0]):
                    return ShortWriteFile(file)
                return file

            writer = store.begin(f"https://content.warframe.com/{archive_name}", 200, len(compressed))
            with mock.patch.object(Path, "open", autospec=True, side_effect=short_extract_open):
                writer.feed(compressed)
                writer.feed(b"")
            self.assertEqual((session / "Warframe.x64.exe").read_bytes(), payload)

    def test_warframe_executable_archive_hash_mismatch_is_not_published(self) -> None:
        executable = b"not the expected executable" * 128
        compressed = lzma.compress(executable, format=lzma.FORMAT_ALONE)
        name = "Warframe.x64.exe.00000000000000000000000000000000.lzma"
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            writer = capture.CaptureStore(session, self.manifest_path_for(session)).begin(
                f"https://content.warframe.com/{name}", 200, len(compressed)
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                writer.feed(compressed)
                writer.feed(b"")
            self.assertFalse((session / "Warframe.x64.exe").exists())
            self.assertTrue((session / "OpenWF" / "Content" / name).is_file())
            self.assertIn("failed MD5 verification", output.getvalue())
            manifest = json.loads(self.manifest_path_for(session).read_text(encoding="utf-8"))
            self.assertEqual(manifest["extraction_errors"], 1)
            self.assertIsNone(manifest["extracted_executable"])
            self.assertGreater(common.session_warning_count(manifest), 0)

    def test_incomplete_stream_is_discarded_and_counted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            store = capture.CaptureStore(session, self.manifest_path_for(session))
            writer = store.begin("https://content.warframe.com/a.bin", 200, expected_size=10)
            with contextlib.redirect_stdout(io.StringIO()):
                writer.feed(b"short")
                writer.feed(b"")
            self.assertFalse((session / "OpenWF" / "Content" / "a.bin").exists())
            self.assertFalse(writer.temporary.exists())
            manifest = json.loads(self.manifest_path_for(session).read_text(encoding="utf-8"))
            self.assertEqual(manifest["incomplete_responses"], 1)

    def test_duplicate_is_not_rewritten(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            store = capture.CaptureStore(session, self.manifest_path_for(session))
            first = store.begin("https://content.warframe.com/a.bin", 200, 3)
            with contextlib.redirect_stdout(io.StringIO()):
                first.feed(b"abc")
                first.feed(b"")
            target = session / "OpenWF" / "Content" / "a.bin"
            original_mtime = target.stat().st_mtime_ns
            second = store.begin("https://content.warframe.com/a.bin", 200, 3)
            with contextlib.redirect_stdout(io.StringIO()):
                second.feed(b"abc")
                second.feed(b"")
            self.assertEqual(target.read_bytes(), b"abc")
            self.assertEqual(target.stat().st_mtime_ns, original_mtime)
            manifest = json.loads(self.manifest_path_for(session).read_text(encoding="utf-8"))
            self.assertEqual(manifest["duplicates"], 1)

    def test_manifest_duplicate_repairs_missing_or_corrupted_capture(self) -> None:
        for label, replacement in (("missing", None), ("corrupted", b"xyz")):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                session = self.make_session(Path(tmp))
                store = capture.CaptureStore(session, self.manifest_path_for(session))
                first = store.begin("https://content.warframe.com/a.bin", 200, 3)
                with contextlib.redirect_stdout(io.StringIO()):
                    first.feed(b"abc")
                    first.feed(b"")

                target = session / "OpenWF" / "Content" / "a.bin"
                if replacement is None:
                    target.unlink()
                else:
                    target.write_bytes(replacement)

                output = io.StringIO()
                second = store.begin("https://content.warframe.com/a.bin", 200, 3)
                with contextlib.redirect_stdout(output):
                    second.feed(b"abc")
                    second.feed(b"")

                self.assertEqual(target.read_bytes(), b"abc")
                self.assertIn("[Saved] 3 B | 200 | /a.bin", output.getvalue())
                manifest = common.read_json_object(self.manifest_path_for(session))
                self.assertEqual(manifest["duplicates"], 0)
                self.assertEqual(manifest["captured_files"], 1)
                self.assertEqual(manifest["captured_bytes"], 3)
                self.assertEqual(manifest["conflict_count"], 0)

    def test_long_capture_name_is_preserved_while_temporary_and_conflict_names_stay_short(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            store = capture.CaptureStore(session, self.manifest_path_for(session))
            name = "a" * 240 + ".cache"
            url = "https://content.warframe.com/" + name
            first = store.begin(url, 200, 3)
            self.assertEqual(first.output.name, name)
            self.assertTrue(first.temporary.name.endswith(".part"))
            self.assertLess(common.utf16_units(first.temporary.name), 64)
            with contextlib.redirect_stdout(io.StringIO()):
                first.feed(b"abc")
                first.feed(b"")
            second = store.begin(url, 200, 3)
            self.assertEqual(second.output.name, name)
            self.assertLess(common.utf16_units(second.temporary.name), 64)
            with contextlib.redirect_stdout(io.StringIO()):
                second.feed(b"xyz")
                second.feed(b"")
            conflicts = list((session / "Conflicts").rglob("*.conflict"))
            self.assertEqual(len(conflicts), 1)
            self.assertLess(common.utf16_units(conflicts[0].name), 64)
            self.assertEqual(conflicts[0].read_bytes(), b"xyz")

    def test_conflict_never_overwrites_first_capture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            store = capture.CaptureStore(session, self.manifest_path_for(session))
            first = store.begin("https://content.warframe.com/a.bin", 200, 3)
            with contextlib.redirect_stdout(io.StringIO()):
                first.feed(b"abc")
                first.feed(b"")
            second = store.begin("https://content.warframe.com/a.bin", 200, 3)
            with contextlib.redirect_stdout(io.StringIO()):
                second.feed(b"xyz")
                second.feed(b"")
            self.assertEqual((session / "OpenWF" / "Content" / "a.bin").read_bytes(), b"abc")
            conflicts = list((session / "Conflicts").rglob("*.conflict"))
            self.assertEqual(len(conflicts), 1)
            self.assertEqual(conflicts[0].read_bytes(), b"xyz")
            manifest = json.loads(self.manifest_path_for(session).read_text(encoding="utf-8"))
            self.assertEqual(manifest["conflict_count"], 1)
            self.assertGreater(common.session_warning_count(manifest), 0)

    def test_repeated_identical_conflict_payload_is_deduplicated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            store = capture.CaptureStore(session, self.manifest_path_for(session))
            for payload in (b"abc", b"xyz", b"xyz"):
                writer = store.begin("https://content.warframe.com/a.bin", 200, len(payload))
                with contextlib.redirect_stdout(io.StringIO()):
                    writer.feed(payload)
                    writer.feed(b"")
            conflicts = list((session / "Conflicts").rglob("*.conflict"))
            self.assertEqual(len(conflicts), 1)
            self.assertEqual(conflicts[0].read_bytes(), b"xyz")
            manifest = common.read_json_object(self.manifest_path_for(session))
            self.assertEqual(manifest["conflict_count"], 1)
            self.assertEqual(manifest["duplicates"], 1)

    def test_case_insensitive_path_collision_never_overwrites_first_capture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            store = capture.CaptureStore(session, self.manifest_path_for(session))
            first = store.begin("https://content.warframe.com/Folder/File.bin", 200, 3)
            with contextlib.redirect_stdout(io.StringIO()):
                first.feed(b"abc")
                first.feed(b"")
            second = store.begin("https://content.warframe.com/folder/file.bin", 200, 3)
            with contextlib.redirect_stdout(io.StringIO()):
                second.feed(b"xyz")
                second.feed(b"")
            self.assertEqual((session / "OpenWF" / "Content" / "Folder" / "File.bin").read_bytes(), b"abc")
            manifest = json.loads(self.manifest_path_for(session).read_text(encoding="utf-8"))
            self.assertEqual(len(manifest["files"]), 1)
            self.assertEqual(manifest["conflict_count"], 1)

    def test_capture_writer_write_failure_does_not_modify_forwarded_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            writer = capture.CaptureStore(session, self.manifest_path_for(session)).begin("https://content.warframe.com/a.bin", 200)
            writer.close()
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(writer.feed(b"client-data"), b"client-data")
            self.assertTrue(writer.failed)

    def test_known_size_capture_waits_for_space_then_reserves_and_releases_it(self) -> None:
        DiskUsage = namedtuple("usage", "total used free")
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            store = capture.CaptureStore(
                session, self.manifest_path_for(session), worker_protocol_enabled=True
            )
            headroom = capture.DISK_SAFETY_HEADROOM_BYTES
            output = io.StringIO()
            with (
                mock.patch.object(
                    capture.shutil,
                    "disk_usage",
                    side_effect=[
                        DiskUsage(200_000_000, 0, headroom + 20_000_000),
                        DiskUsage(200_000_000, 0, headroom + 5_000_000),
                        DiskUsage(200_000_000, 0, headroom + 35_000_000),
                    ],
                ),
                mock.patch.object(capture.time, "sleep"),
                contextlib.redirect_stdout(output),
            ):
                first = store.begin("https://content.warframe.com/first.bin", 200, 20_000_000)
                second = store.begin("https://content.warframe.com/second.bin", 200, 10_000_000)
                first.abort()
                second.abort()
            self.assertEqual(store.reserved_bytes, 0)
            self.assertTrue(any(message.get("type") == "waiting" for message in worker_messages(output.getvalue())))
            self.assertIn({"type": "progress_clear"}, worker_messages(output.getvalue()))

    def test_unknown_size_response_waits_for_space_and_continues_same_capture(self) -> None:
        DiskUsage = namedtuple("usage", "total used free")
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            store = capture.CaptureStore(
                session, self.manifest_path_for(session), worker_protocol_enabled=True
            )
            output = io.StringIO()
            headroom = capture.DISK_SAFETY_HEADROOM_BYTES
            with (
                mock.patch.object(
                    capture.shutil,
                    "disk_usage",
                    side_effect=[
                        DiskUsage(headroom + 100, 0, headroom + 10),
                        DiskUsage(headroom + 100, 0, headroom + 4),
                        DiskUsage(headroom + 100, 0, headroom + 9),
                    ],
                ),
                mock.patch.object(capture.time, "sleep"),
                contextlib.redirect_stdout(output),
            ):
                writer = store.begin("https://content.warframe.com/chunked.bin", 200)
                self.assertEqual(writer.feed(b"123456"), b"123456")
                self.assertEqual(writer.feed(b"12345"), b"12345")
                writer.feed(b"")
            self.assertFalse(writer.failed)
            self.assertEqual((session / "OpenWF" / "Content" / "chunked.bin").read_bytes(), b"12345612345")
            self.assertEqual(store.reserved_bytes, 0)
            manifest = common.read_json_object(self.manifest_path_for(session))
            self.assertNotIn("skipped_space", manifest)
            self.assertEqual(manifest["capture_errors"], 0)
            self.assertTrue(any(message.get("type") == "waiting" for message in worker_messages(output.getvalue())))

    def test_known_size_response_waits_until_it_can_be_captured(self) -> None:
        DiskUsage = namedtuple("usage", "total used free")
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            addon = capture.CaptureAddon(
                session, self.manifest_path_for(session), worker_protocol_enabled=True
            )
            flow = self.fake_flow(200, content_length="100")
            output = io.StringIO()
            headroom = capture.DISK_SAFETY_HEADROOM_BYTES
            with (
                mock.patch.object(
                    capture.shutil,
                    "disk_usage",
                    side_effect=[
                        DiskUsage(headroom + 200, 0, headroom + 50),
                        DiskUsage(headroom + 300, 0, headroom + 200),
                    ],
                ),
                mock.patch.object(capture.time, "sleep"),
                contextlib.redirect_stdout(output),
            ):
                addon.responseheaders(flow)
                self.assertTrue(callable(flow.response.stream))
                flow.response.stream(b"x" * 100)
                flow.response.stream(b"")
            self.assertEqual((session / "OpenWF" / "Content" / "a.bin").read_bytes(), b"x" * 100)
            manifest = common.read_json_object(self.manifest_path_for(session))
            self.assertNotIn("skipped_space", manifest)
            self.assertEqual(manifest["capture_errors"], 0)
            self.assertEqual(common.session_warning_count(manifest), 0)
            self.assertTrue(any(message.get("type") == "waiting" for message in worker_messages(output.getvalue())))

    def test_disk_full_write_waits_and_resumes_exact_unwritten_offset(self) -> None:
        DiskUsage = namedtuple("usage", "total used free")

        class PartialThenDiskFullFile:
            def __init__(self):
                self.data = bytearray()
                self.calls = 0
                self.closed = False

            def write(self, data) -> int:
                payload = bytes(data)
                self.calls += 1
                if self.calls == 1:
                    self.data.extend(payload[:3])
                    return 3
                if self.calls == 2:
                    raise OSError(errno.ENOSPC, "disk full")
                self.data.extend(payload)
                return len(payload)

            def close(self) -> None:
                self.closed = True

        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            store = capture.CaptureStore(
                session, self.manifest_path_for(session), worker_protocol_enabled=True
            )
            writer = store.begin("https://content.warframe.com/a.bin", 200, 6)
            writer.close()
            fake_file = PartialThenDiskFullFile()
            writer._file = fake_file
            headroom = capture.DISK_SAFETY_HEADROOM_BYTES
            output = io.StringIO()
            with (
                mock.patch.object(
                    capture.shutil,
                    "disk_usage",
                    side_effect=[
                        DiskUsage(headroom + 10, 0, headroom + 2),
                        DiskUsage(headroom + 20, 0, headroom + 20),
                    ],
                ),
                mock.patch.object(capture.time, "sleep"),
                contextlib.redirect_stdout(output),
            ):
                self.assertEqual(writer.feed(b"abcdef"), b"abcdef")

            self.assertEqual(bytes(fake_file.data), b"abcdef")
            self.assertFalse(writer.failed)
            self.assertFalse(store.capture_disabled)
            self.assertEqual(store.reserved_bytes, 0)
            self.assertEqual(store.manifest["disk_full_errors"], 1)
            self.assertTrue(any(message.get("type") == "waiting" for message in worker_messages(output.getvalue())))
            writer.abort()

    def test_disk_full_during_publish_waits_instead_of_aborting_capture(self) -> None:
        DiskUsage = namedtuple("usage", "total used free")
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            store = capture.CaptureStore(session, self.manifest_path_for(session))
            writer = store.begin("https://content.warframe.com/a.bin", 200, 3)
            writer.feed(b"abc")
            headroom = capture.DISK_SAFETY_HEADROOM_BYTES
            with (
                mock.patch.object(
                    store,
                    "publish",
                    side_effect=[OSError(errno.ENOSPC, "disk full"), "saved"],
                ) as publish,
                mock.patch.object(
                    capture.shutil,
                    "disk_usage",
                    return_value=DiskUsage(headroom + 10, 0, headroom + 10),
                ),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                writer.feed(b"")
            self.assertEqual(publish.call_count, 2)
            self.assertFalse(writer.failed)
            self.assertEqual(writer.publish_result, "saved")
            self.assertFalse(store.capture_disabled)

    def test_metadata_disk_full_does_not_disable_capture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            store = capture.CaptureStore(session, self.manifest_path_for(session))
            output = io.StringIO()
            with (
                mock.patch.object(
                    capture,
                    "atomic_write_json",
                    side_effect=[OSError(errno.ENOSPC, "disk full"), None],
                ),
                contextlib.redirect_stdout(output),
            ):
                with store.lock:
                    self.assertFalse(store._write_manifest_locked())
                    self.assertTrue(store._write_manifest_locked())
            self.assertFalse(store.capture_disabled)
            self.assertEqual(store.manifest["disk_full_errors"], 1)
            self.assertIn("WARNING:", output.getvalue())

    def test_addon_done_aborts_active_partial_writers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            addon = capture.CaptureAddon(session, self.manifest_path_for(session))
            writer = addon.store.begin("https://content.warframe.com/a.bin", 200, 100)
            writer.feed(b"partial")
            with contextlib.redirect_stdout(io.StringIO()):
                addon.done()
            self.assertFalse(writer.temporary.exists())
            self.assertFalse(addon.store.active_writers)
            manifest = json.loads(self.manifest_path_for(session).read_text(encoding="utf-8"))
            self.assertEqual(manifest["incomplete_responses"], 1)

    def test_responseheaders_only_streams_complete_200_responses(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            addon = self.make_addon(Path(tmp))
            try:
                ok = self.fake_flow(200, content_length="3")
                addon.responseheaders(ok)
                self.assertTrue(callable(ok.response.stream))
                with contextlib.redirect_stdout(io.StringIO()):
                    ok.response.stream(b"abc")
                    ok.response.stream(b"")

                for status in (206, 301, 304, 404, 500):
                    flow = self.fake_flow(status)
                    with contextlib.redirect_stdout(io.StringIO()):
                        addon.responseheaders(flow)
                    self.assertIs(flow.response.stream, capture.passthrough_stream)

                failed = self.fake_flow(200)
                with mock.patch.object(addon.store, "begin", side_effect=OSError("capture open failed")), contextlib.redirect_stdout(io.StringIO()):
                    addon.responseheaders(failed)
                self.assertIs(failed.response.stream, capture.passthrough_stream)
            finally:
                # Windows cannot remove an open .part file. Always run the addon shutdown path
                # before TemporaryDirectory cleanup, even if an assertion above fails.
                with contextlib.redirect_stdout(io.StringIO()):
                    addon.done()

            self.assertFalse(addon.store.active_writers)

    def test_response_statuses_are_recorded_for_real_capture_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            addon = capture.CaptureAddon(session, self.manifest_path_for(session))
            with contextlib.redirect_stdout(io.StringIO()):
                addon.responseheaders(self.fake_flow(206))
                addon.responseheaders(self.fake_flow(404))
            manifest = json.loads(self.manifest_path_for(session).read_text(encoding="utf-8"))
            self.assertEqual(manifest["responses_seen"], 2)
            self.assertEqual(manifest["http_statuses"], {"206": 1, "404": 1})
            self.assertEqual(manifest["skipped_partial"], 1)
            self.assertEqual(manifest["skipped_http"], 1)

    def test_non_target_flow_is_not_streamed_and_debug_only_names_host(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            addon = self.make_addon(Path(tmp), debug=True)
            flow = self.fake_flow(200, host="example.com", url="https://example.com/private/token?secret=yes")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                addon.responseheaders(flow)
            text = output.getvalue()
            self.assertIn("Filtered host: example.com", text)
            self.assertNotIn("private", text)
            self.assertNotIn("secret", text)

    def test_global_debug_non_target_flow_logs_one_ignored_line_without_private_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            addon = self.make_addon(Path(tmp), debug="global")
            flow = self.fake_flow(200, host="example.com", url="https://example.com/private/token?secret=yes")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                addon.requestheaders(flow)
                addon.responseheaders(flow)
            lines = [line for line in output.getvalue().splitlines() if line]
            self.assertEqual(len(lines), 1)
            self.assertIn("https://example.com/ (ignored)", lines[0])
            self.assertNotIn("Request:", lines[0])
            self.assertNotIn("Filtered host", lines[0])
            self.assertNotIn("private", lines[0])
            self.assertNotIn("secret", lines[0])

    def test_global_debug_target_request_is_not_logged_before_final_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            addon = self.make_addon(Path(tmp), debug="global")
            flow = self.fake_flow(200, url="https://content.warframe.com/private/token?secret=yes")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                addon.requestheaders(flow)
            self.assertEqual(output.getvalue(), "")

    def test_global_debug_logs_ignored_passthrough_from_next_layer_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            addon = self.make_addon(Path(tmp), debug="global")
            ignored_layer_type = type("TCPLayer", (), {})
            ignored_layer = ignored_layer_type()
            ignored_layer.flow = None
            client = SimpleNamespace(transport_protocol="tcp")
            server = SimpleNamespace(address=("93.184.216.34", 80), peername=None)
            context = SimpleNamespace(client=client, server=server)
            nextlayer = SimpleNamespace(
                layer=ignored_layer,
                context=context,
                data_client=lambda: b"GET /private HTTP/1.1\r\nHost: example.com\r\n\r\n",
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                addon.next_layer(nextlayer)
                addon.next_layer(nextlayer)
            lines = [line for line in output.getvalue().splitlines() if line]
            self.assertEqual(len(lines), 1)
            self.assertIn("http://example.com/ (ignored)", lines[0])
            self.assertNotIn("Request:", lines[0])
            self.assertNotIn("private", lines[0])

    def test_dns_hostname_cache_expires_and_reports_shared_ip_names(self) -> None:
        now = [100.0]
        cache = capture.DNSHostnameCache(clock=lambda: now[0])
        cache.remember("93.184.216.34", "example.com.", 60)
        self.assertEqual(cache.lookup("93.184.216.34"), ("example.com", 0))
        now[0] += 1
        cache.remember("93.184.216.34", "cdn.example.com", 60)
        self.assertEqual(cache.lookup("93.184.216.34"), ("cdn.example.com", 1))
        self.assertEqual(
            capture.annotate_dns_hint("udp://93.184.216.34:443", cache.lookup("93.184.216.34")),
            "udp://93.184.216.34:443 [DNS: cdn.example.com +1 other]",
        )
        now[0] += 1
        cache.remember("93.184.216.34", "assets.example.com", 60)
        self.assertEqual(
            capture.annotate_dns_hint("udp://93.184.216.34:443", cache.lookup("93.184.216.34")),
            "udp://93.184.216.34:443 [DNS: assets.example.com +2 others]",
        )
        now[0] += 61
        self.assertIsNone(cache.lookup("93.184.216.34"))

    def test_global_debug_promotes_plaintext_udp_dns_without_logging_server_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            addon = self.make_addon(Path(tmp), debug="global")
            ignored_layer_type = type("UDPLayer", (), {})
            ignored_layer = ignored_layer_type()
            ignored_layer.flow = None
            client = SimpleNamespace(transport_protocol="udp")
            server = SimpleNamespace(address=("10.162.178.46", 53), peername=None)
            context = SimpleNamespace(client=client, server=server)
            nextlayer = SimpleNamespace(layer=ignored_layer, context=context, data_client=lambda: b"dns-query")

            class FakeDNSLayer:
                def __init__(self, layer_context):
                    self.context = layer_context

            dns_module = ModuleType("mitmproxy.dns")
            dns_module.DNSMessage = SimpleNamespace(unpack=lambda data: SimpleNamespace(query=True))
            layers_module = ModuleType("mitmproxy.proxy.layers")
            layers_module.DNSLayer = FakeDNSLayer
            proxy_module = ModuleType("mitmproxy.proxy")
            proxy_module.__path__ = []
            proxy_module.layers = layers_module
            mitmproxy_module = ModuleType("mitmproxy")
            mitmproxy_module.__path__ = []
            mitmproxy_module.dns = dns_module
            mitmproxy_module.proxy = proxy_module
            modules = {
                "mitmproxy": mitmproxy_module,
                "mitmproxy.dns": dns_module,
                "mitmproxy.proxy": proxy_module,
                "mitmproxy.proxy.layers": layers_module,
            }
            output = io.StringIO()
            with mock.patch.dict(sys.modules, modules), contextlib.redirect_stdout(output):
                addon.next_layer(nextlayer)
            self.assertIsInstance(nextlayer.layer, FakeDNSLayer)
            self.assertEqual(output.getvalue(), "")

    def test_global_debug_dns_query_learns_answer_for_later_raw_ip_annotation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            addon = self.make_addon(Path(tmp), debug="global")
            question = SimpleNamespace(name="cdn.discordapp.com.", type=1)
            request = SimpleNamespace(questions=[question])
            answer = SimpleNamespace(name="cdn.discordapp.com.", type=1, ttl=120, data=b"\x5d\xb8\xd8\x22")
            response = SimpleNamespace(answers=[answer], additionals=[])
            flow = SimpleNamespace(request=request, response=response)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                addon.dns_response(flow)
            self.assertEqual(output.getvalue(), "")

            ignored_layer_type = type("UDPLayer", (), {})
            ignored_layer = ignored_layer_type()
            ignored_layer.flow = None
            client = SimpleNamespace(transport_protocol="udp")
            server = SimpleNamespace(address=("93.184.216.34", 6881), peername=None)
            context = SimpleNamespace(client=client, server=server)
            nextlayer = SimpleNamespace(layer=ignored_layer, context=context, data_client=lambda: b"not-quic")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                addon.next_layer(nextlayer)
            self.assertIn("udp://93.184.216.34:6881 [DNS: cdn.discordapp.com] (ignored)", output.getvalue())

    def test_global_debug_mdns_is_silent_and_never_promoted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            addon = self.make_addon(Path(tmp), debug="global")
            ignored_layer_type = type("UDPLayer", (), {})
            ignored_layer = ignored_layer_type()
            ignored_layer.flow = None
            client = SimpleNamespace(transport_protocol="udp")
            server = SimpleNamespace(address=("224.0.0.251", 5353), peername=None)
            context = SimpleNamespace(client=client, server=server)
            nextlayer = SimpleNamespace(layer=ignored_layer, context=context, data_client=lambda: b"mdns")
            output = io.StringIO()
            with mock.patch.object(addon, "_promote_dns_passthrough", wraps=addon._promote_dns_passthrough) as promote, contextlib.redirect_stdout(output):
                addon.next_layer(nextlayer)
            self.assertIs(nextlayer.layer, ignored_layer)
            self.assertEqual(output.getvalue(), "")
            promote.assert_not_called()

    def test_global_debug_malformed_udp_dns_stays_raw_passthrough_and_silent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            addon = self.make_addon(Path(tmp), debug="global")
            ignored_layer_type = type("UDPLayer", (), {})
            ignored_layer = ignored_layer_type()
            ignored_layer.flow = None
            client = SimpleNamespace(transport_protocol="udp")
            server = SimpleNamespace(address=("10.162.178.46", 53), peername=None)
            context = SimpleNamespace(client=client, server=server)
            nextlayer = SimpleNamespace(layer=ignored_layer, context=context, data_client=lambda: b"not-dns")
            dns_module = ModuleType("mitmproxy.dns")

            def bad_unpack(data):
                raise ValueError("not DNS")

            dns_module.DNSMessage = SimpleNamespace(unpack=bad_unpack)
            layers_module = ModuleType("mitmproxy.proxy.layers")
            layers_module.DNSLayer = object
            proxy_module = ModuleType("mitmproxy.proxy")
            proxy_module.__path__ = []
            proxy_module.layers = layers_module
            mitmproxy_module = ModuleType("mitmproxy")
            mitmproxy_module.__path__ = []
            mitmproxy_module.dns = dns_module
            mitmproxy_module.proxy = proxy_module
            modules = {
                "mitmproxy": mitmproxy_module,
                "mitmproxy.dns": dns_module,
                "mitmproxy.proxy": proxy_module,
                "mitmproxy.proxy.layers": layers_module,
            }
            output = io.StringIO()
            with mock.patch.dict(sys.modules, modules), contextlib.redirect_stdout(output):
                addon.next_layer(nextlayer)
            self.assertIs(nextlayer.layer, ignored_layer)
            self.assertEqual(output.getvalue(), "")

    def test_error_hook_discards_partial_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            addon = self.make_addon(Path(tmp))
            flow = self.fake_flow(200)
            addon.responseheaders(flow)
            writer = flow.metadata["nct_writer"]
            writer.feed(b"partial")
            with contextlib.redirect_stdout(io.StringIO()):
                addon.error(flow)
            self.assertFalse(writer.temporary.exists())
            manifest = json.loads((addon.store.manifest_path).read_text(encoding="utf-8"))
            self.assertEqual(manifest["incomplete_responses"], 1)

    def test_global_debug_keeps_target_host_filter_for_safe_passthrough(self) -> None:
        captured: dict[str, object] = {}

        class FakeOptions:
            def __init__(self, **kwargs):
                captured["kwargs"] = kwargs

        class FakeAddons:
            def add(self, addon):
                captured["addon"] = addon

        class FakeMaster:
            def __init__(self, options, with_termlog=False, with_dumper=False):
                self.addons = FakeAddons()

            async def run(self):
                return None

            def shutdown(self):
                pass

        mitmproxy = mock.MagicMock()
        mitmproxy.options.Options = FakeOptions
        dump = mock.MagicMock()
        dump.DumpMaster = FakeMaster
        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp) / "session"
            confdir = Path(tmp) / "conf"
            with (
                mock.patch.dict(nct.sys.modules, {"mitmproxy": mitmproxy, "mitmproxy.tools": mock.MagicMock(), "mitmproxy.tools.dump": dump}),
                mock.patch.object(common, "mitmproxy_conf_directory", return_value=confdir),
                mock.patch.object(capture, "CaptureAddon", return_value=object()),
                mock.patch.object(nct, "patch_mitmproxy_1223_quic_host_filter", return_value=True),
            ):
                nct.asyncio.run(nct.run_proxy_worker(session, "local", 0, "global", manifest_path=Path(tmp) / "session_session.json"))
            self.assertEqual(captured["kwargs"]["allow_hosts"], [common.ALLOW_HOSTS_REGEX])

            captured.clear()
            with (
                mock.patch.dict(nct.sys.modules, {"mitmproxy": mitmproxy, "mitmproxy.tools": mock.MagicMock(), "mitmproxy.tools.dump": dump}),
                mock.patch.object(common, "mitmproxy_conf_directory", return_value=confdir),
                mock.patch.object(capture, "CaptureAddon", return_value=object()),
            ):
                nct.asyncio.run(nct.run_proxy_worker(session, "local:Launcher.exe", 0, "on", manifest_path=Path(tmp) / "session_session.json"))
            self.assertEqual(captured["kwargs"]["allow_hosts"], [common.ALLOW_HOSTS_REGEX])

    def test_port_preflight_requests_exclusive_bind_when_supported(self) -> None:
        sock = mock.MagicMock()
        sock.__enter__.return_value = sock
        with mock.patch.object(windows_proxy.socket, "SO_EXCLUSIVEADDRUSE", 12345, create=True), mock.patch.object(
            windows_proxy.socket, "socket", return_value=sock
        ):
            windows_proxy.ensure_port_available(8080)
        sock.setsockopt.assert_called_once_with(windows_proxy.socket.SOL_SOCKET, 12345, 1)
        sock.bind.assert_called_once_with(("127.0.0.1", 8080))

    def test_recovery_format_has_before_and_applied_and_uses_user_wide_runtime_state(self) -> None:
        before = self.proxy_settings(ProxyEnable={"value": 0, "type": 4})
        applied = windows_proxy.build_local_proxy_settings(before, 8080)
        state = windows_proxy.make_recovery_state(before, applied, Path("C:/session"), 8080)
        self.assertEqual(windows_proxy.RECOVERY_VERSION, 1)
        self.assertEqual(state["version"], 1)
        self.assertEqual(state["application_version"], common.VERSION)
        self.assertEqual(state["before"], before)
        self.assertEqual(state["applied"], applied)
        with tempfile.TemporaryDirectory() as state_tmp:
            local_root = Path(state_tmp) / "DarkLotus" / "Ninja Capture Tool"
            with mock.patch.object(common, "nct_local_app_data_root", return_value=local_root):
                recovery_path = common.proxy_recovery_file()
            self.assertEqual(recovery_path, local_root / "state" / "proxy_recovery.json")

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "proxy_recovery.json"
            with (
                mock.patch.object(windows_proxy, "apply_proxy_settings", side_effect=[RuntimeError("apply failed"), RuntimeError("restore failed")]),
                mock.patch.object(windows_proxy, "get_proxy_settings"),
            ):
                with self.assertRaisesRegex(
                    RuntimeError,
                    r"Could not enable System Proxy .*restoring the previous Windows proxy settings also failed: restore failed.*Recovery data was kept",
                ):
                    windows_proxy.activate_local_proxy(before, Path(tmp), 8080, path)
            self.assertTrue(path.exists())

    def test_recovery_rejects_unsupported_format_version(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "Unsupported proxy recovery format"):
            windows_proxy.validate_recovery_state({"version": 2, "proxy_settings": {}})

    def test_deactivate_restores_safe_partial_ninja_capture_tool_transition(self) -> None:
        before = self.proxy_settings(ProxyEnable={"value": 0, "type": 4}, ProxyServer=None)
        applied = windows_proxy.build_local_proxy_settings(before, 8080)
        current = dict(applied)
        current["ProxyEnable"] = before["ProxyEnable"]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "proxy_recovery.json"
            path.write_text("owned", encoding="utf-8")
            with (
                mock.patch.object(windows_proxy, "get_proxy_settings", side_effect=[current, before]),
                mock.patch.object(windows_proxy, "apply_proxy_settings") as restore,
            ):
                self.assertTrue(windows_proxy.deactivate_local_proxy(before, applied, path))
            restore.assert_called_once_with(before)
            self.assertFalse(path.exists())

    def test_content_transition_without_previous_manifest_baseline_stays_explicitly_uncertain(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None)
        session = nct.CaptureSession(options)
        session.steam_tracking_state_loaded = True
        with (
            mock.patch.object(live_tracking, "load_warframe_version_high_water", return_value="43.5.4"),
            mock.patch.object(live_tracking, "save_warframe_version_high_water"),
        ):
            version_info, messages = session._apply_current_warframe_version_result(
                "44.0", None, announce_current=True
            )
        _, steam_messages = session._apply_current_steam_manifest_result(
            {
                "app_id": 230410,
                "depot_id": 230411,
                "manifest_id": 4895911296145320793,
                "size": 52 * 1024**3,
                "download_size": 30 * 1024**3,
                "status": "valid",
                "last_updated": 0,
                "change_number": 0,
                "source": "test",
                "source_kind": "live",
            },
            None,
            announce_current=True,
            content_update=True,
        )
        messages.extend(steam_messages)
        self.assertTrue(version_info["content_update"])
        self.assertIn(("info", "[Warframe] Live version: U44.0"), messages)
        self.assertTrue(any(message.startswith("[Steam] Previous manifest baseline is unknown;") for _, message in messages))
        self.assertIsNone(session.awaiting_content_branch)
        self.assertEqual(session.last_valid_steam_manifest_id, 4895911296145320793)

    def test_pending_content_wait_without_manifest_baseline_resolves_as_unknown(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None)
        session = nct.CaptureSession(options)
        session.steam_tracking_state_loaded = True
        session.awaiting_content_branch = "44.0"
        session.awaiting_from_manifest_id = None
        session.live_warframe_version = "44.0"
        info = {
            "manifest_id": 843737746734465482,
            "size": 53 * 1024**3,
            "status": "valid",
            "source": "Steam live query",
            "source_kind": "live",
        }
        _, messages = session._apply_current_steam_manifest_result(
            info,
            None,
            announce_current=False,
            content_update=False,
        )
        self.assertIsNone(session.awaiting_content_branch)
        self.assertEqual(session.last_valid_steam_manifest_id, 843737746734465482)
        self.assertTrue(any(message.startswith("[Steam] Previous manifest baseline is unknown;") for _, message in messages))

    def test_first_cached_result_then_direct_live_query_establishes_live_baseline(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None)
        session = nct.CaptureSession(options)
        session.steam_tracking_state_loaded = True
        session.live_steam_manifest = live_tracking.SteamManifestObservation(111, "valid", 52 * 1024**3, "cache")
        self.assertIsNone(session.last_valid_steam_manifest_id)
        _, messages = session._apply_current_steam_manifest_result(
            {
                "manifest_id": 222,
                "size": 53 * 1024**3,
                "status": "valid",
                "source": "Steam live query",
                "source_kind": "live",
            },
            None,
            announce_current=False,
            content_update=False,
        )
        text = "\n".join(message for _, message in messages)
        self.assertIn("Direct live query recovered; live manifest: 222 (53.0 GiB).", text)
        self.assertNotIn("New live manifest candidate", text)
        self.assertNotIn("Live manifest changed", text)
        self.assertEqual(session.last_valid_steam_manifest_id, 222)
        self.assertEqual(session.last_valid_steam_manifest_size, 53 * 1024**3)
        self.assertIsNone(session.pre_transition_manifest_id)

    def test_manifest_result_without_provenance_is_not_treated_as_live(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None)
        session = nct.CaptureSession(options)
        session.steam_tracking_state_loaded = True
        result, messages = session._apply_current_steam_manifest_result(
            {
                "manifest_id": 123,
                "size": 52 * 1024**3,
                "status": "valid",
                "source": "Steam live query",
            },
            None,
            announce_current=False,
            content_update=False,
        )
        self.assertIsNone(result["manifest_id"])
        self.assertEqual(session.live_steam_error, "invalid Steam manifest source")
        self.assertIsNone(session.live_steam_manifest)
        self.assertEqual(messages, [])

    def test_direct_failure_without_cache_is_header_only_without_redundant_detail_log(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None)
        session = nct.CaptureSession(options)
        session.steam_tracking_state_loaded = True
        _, messages = session._apply_current_steam_manifest_result(
            None,
            f"pysteam-client[client] {common.STEAM_CLIENT_VERSION} is required for live Steam manifest queries",
            announce_current=True,
            content_update=False,
        )
        self.assertEqual(messages, [])
        self.assertEqual(
            session._current_steam_status_line(),
            "[Steam] Live manifest unavailable (Steam client dependency missing).",
        )
        session.live_status_header_initialized = True
        with mock.patch.object(session, "_set_live_status_line"), mock.patch.object(session, "_record_live_status_log") as record:
            session._refresh_steam_status_header()
        record.assert_not_called()

    def test_live_check_interval_uses_seconds(self) -> None:
        config = dict(nct_config.DEFAULT_CONFIG, live_check_interval_seconds=1)
        args = nct_config.build_argument_parser().parse_args([])
        options = nct_config.resolve_runtime_options(args, config)
        self.assertEqual(options["live_check_interval_seconds"], 1)
        session = nct.CaptureSession(dict(options, output_path=None))
        with mock.patch.object(live_tracking.time, "monotonic", return_value=100.0):
            session._schedule_next_live_check()
        self.assertEqual(session.next_live_check_at, 101.0)

    def test_failed_version_lookup_never_reuses_saved_version_for_automatic_naming(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            options = dict(
                nct_config.DEFAULT_CONFIG,
                output_root=root,
                output_path=None,
                name_session_after_warframe_version=True,
            )
            session = nct.CaptureSession(options)
            with mock.patch.object(
                live_tracking, "load_warframe_version_high_water", return_value="43.5.4"
            ) as load_saved:
                info, messages = session._apply_current_warframe_version_result(
                    None, "offline", announce_current=True
                )
            load_saved.assert_called_once_with()
            self.assertEqual(info["status"], "unavailable")
            self.assertEqual(info["previous_version"], "43.5.4")
            target, _, session_naming = session._create_automatic_session_directory(root, info, messages)
            self.assertNotEqual(target.name, "43.5.4")
            self.assertRegex(target.name, r"^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}(?:_\d+)?$")
            self.assertEqual(session_naming, "timestamp")
            self.assertIn(("info", "[Session] Automatic version naming unavailable; using timestamp session name instead."), messages)

    def test_unavailable_version_manifest_keeps_previous_value_as_context_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            options = dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None, name_session_after_warframe_version=True)
            session = nct.CaptureSession(options)
            with mock.patch.object(
                live_tracking, "load_warframe_version_high_water", return_value="43.5.4"
            ):
                info, messages = session._apply_current_warframe_version_result(
                    None, "offline", announce_current=True
                )
            target, session_id, session_naming = session._create_automatic_session_directory(root, info, messages)
            manifest_path = common.session_artifact_paths(root, session_id)[1]
            capture.initialize_session_manifest(
                target,
                options,
                manifest_path,
                warframe_version_info=info,
                session_naming=session_naming,
            )
            data = common.read_json_object(manifest_path)
            self.assertIsNone(data["warframe_version"])
            self.assertEqual(data["warframe_version_status"], "unavailable")
            self.assertEqual(data["warframe_version_previous"], "43.5.4")
            self.assertEqual(data["session_naming"], "timestamp")
            self.assertNotEqual(target.name, "43.5.4")

    def test_version_naming_failure_falls_back_to_timestamp_without_cached_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            options = dict(
                nct_config.DEFAULT_CONFIG,
                output_root=root,
                output_path=None,
                name_session_after_warframe_version=True,
            )
            session = nct.CaptureSession(options)
            messages: list[tuple[str, str]] = []
            target, session_id, session_naming = session._create_automatic_session_directory(
                root,
                {
                    "version": None,
                    "checked_at": "now",
                    "status": "unavailable",
                    "previous_version": None,
                },
                messages,
            )
            self.assertRegex(target.name, r"^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}(?:_\d+)?$")
            self.assertEqual(target.name, session_id)
            self.assertEqual(session_naming, "timestamp")
            self.assertIn(
                ("info", "[Session] Automatic version naming unavailable; using timestamp session name instead."),
                messages,
            )

    def test_version_naming_uses_matching_folder_and_sidecar_prefixes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            options = dict(
                nct_config.DEFAULT_CONFIG,
                output_root=root,
                output_path=None,
                name_session_after_warframe_version=True,
            )
            session = nct.CaptureSession(options)
            info = {
                "version": "43.5.4",
                "checked_at": "now",
                "status": "current",
                "previous_version": "43.5.4",
            }
            first, first_id, first_naming = session._create_automatic_session_directory(root, info, [])
            first_log, first_manifest = common.session_artifact_paths(root, first_id)
            first_log.touch()
            first_manifest.write_text("{}", encoding="utf-8")
            second, second_id, second_naming = session._create_automatic_session_directory(root, info, [])
            second_log, second_manifest = common.session_artifact_paths(root, second_id)
            self.assertEqual(first.name, "43.5.4")
            self.assertEqual(first_id, "43.5.4")
            self.assertEqual(first_log.name, "43.5.4_capture.log")
            self.assertEqual(first_manifest.name, "43.5.4_session.json")
            self.assertEqual(second.name, "43.5.4_2")
            self.assertEqual(second_id, "43.5.4_2")
            self.assertEqual(second_log.name, "43.5.4_2_capture.log")
            self.assertEqual(second_manifest.name, "43.5.4_2_session.json")
            self.assertEqual(first_naming, "warframe_version")
            self.assertEqual(second_naming, "warframe_version")

    def test_final_manifest_status_is_based_on_warning_counters(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = self.make_session(Path(tmp))
            manifest = json.loads(self.manifest_path_for(session).read_text(encoding="utf-8"))
            self.assertEqual(common.session_warning_count(manifest), 0)
            manifest["skipped_partial"] = 1
            self.assertEqual(common.session_warning_count(manifest), 1)

    def test_capture_activity_lock_path_is_installation_scoped_under_local_app_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            install = Path(tmp) / "install"
            local_root = Path(tmp) / "local" / "DarkLotus" / "Ninja Capture Tool"
            with mock.patch.object(common, "nct_local_app_data_root", return_value=local_root):
                first = common.capture_activity_lock_path(install)
                second = common.capture_activity_lock_path(Path(tmp) / "other-install")
            self.assertEqual(first.parent, local_root / "locks")
            self.assertTrue(first.name.endswith(".capture.lock"))
            self.assertNotEqual(first, second)

    def test_windows_file_lock_reports_contention_with_typed_error(self) -> None:
        busy = OSError(errno.EACCES, "busy")
        fake_msvcrt = SimpleNamespace(
            LK_NBLCK=1,
            LK_UNLCK=2,
            locking=mock.MagicMock(side_effect=busy),
        )
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(sys.modules, {"msvcrt": fake_msvcrt}):
            with self.assertRaisesRegex(common.FileLockBusyError, "already running"):
                with common.windows_file_lock(
                    Path(tmp) / "capture.lock",
                    0,
                    "Another Ninja Capture Tool capture is already running.",
                ):
                    pass

    def test_capture_activity_probe_does_not_hide_access_denied_as_contention(self) -> None:
        denied = OSError(errno.EACCES, "access denied")
        denied.winerror = 5
        with (
            mock.patch.object(instance_lock.os, "name", "nt"),
            mock.patch.object(instance_lock, "windows_file_lock", side_effect=denied),
        ):
            with self.assertRaises(OSError) as raised:
                instance_lock.another_capture_is_active()
        self.assertIs(raised.exception, denied)

    def test_capture_lock_does_not_hide_access_denied_as_contention(self) -> None:
        denied = OSError(errno.EACCES, "access denied")
        denied.winerror = 5
        with (
            mock.patch.object(instance_lock.os, "name", "nt"),
            mock.patch.object(instance_lock, "windows_file_lock", side_effect=denied),
        ):
            with self.assertRaises(OSError) as raised:
                with instance_lock.capture_lock():
                    pass
        self.assertIs(raised.exception, denied)

    @unittest.skipUnless(os.name == "nt", "Windows cross-process capture lock test")
    def test_capture_activity_lock_rejects_a_second_process_for_same_installation(self) -> None:
        root = Path(__file__).resolve().parents[1]
        code = (
            "import sys; from pathlib import Path; import common, instance_lock; "
            "instance_lock.TOOL_DIR = Path(sys.argv[1]); "
            "common.nct_local_app_data_root = lambda: Path(sys.argv[2]); "
            "\ntry:\n"
            "    with instance_lock.capture_lock():\n"
            "        raise SystemExit(3)\n"
            "except RuntimeError as exc:\n"
            "    print(exc)\n"
            "    raise SystemExit(0)\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            install = Path(tmp) / "install"
            install.mkdir()
            with mock.patch.object(instance_lock, "TOOL_DIR", install):
                with instance_lock.capture_lock():
                    result = subprocess.run(
                        [sys.executable, "-B", "-c", code, str(install), str(self._local_app_data_root)],
                        cwd=root,
                        capture_output=True,
                        text=True,
                        timeout=15,
                        check=False,
                    )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Another Ninja Capture Tool capture is already running", result.stdout)

    @unittest.skipUnless(os.name == "nt", "Windows cross-install capture lock test")
    def test_capture_activity_lock_rejects_a_second_installation_for_same_user(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            first_install = Path(tmp) / "first-install"
            other_install = Path(tmp) / "other-install"
            first_install.mkdir()
            other_install.mkdir()
            code = (
                "import sys; from pathlib import Path; import common, instance_lock; "
                "instance_lock.TOOL_DIR = Path(sys.argv[1]); "
                "common.nct_local_app_data_root = lambda: Path(sys.argv[2]); "
                "\ntry:\n"
                "    with instance_lock.capture_lock():\n"
                "        raise SystemExit(3)\n"
                "except RuntimeError as exc:\n"
                "    print(exc)\n"
                "    raise SystemExit(0)\n"
            )
            with mock.patch.object(instance_lock, "TOOL_DIR", first_install):
                with instance_lock.capture_lock():
                    result = subprocess.run(
                        [sys.executable, "-B", "-c", code, str(other_install), str(self._local_app_data_root)],
                        cwd=root,
                        capture_output=True,
                        text=True,
                        timeout=15,
                        check=False,
                    )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Another Ninja Capture Tool capture is already running", result.stdout)

    def test_certificate_install_uses_local_machine_cryptoapi_store(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            certificate = Path(tmp) / "mitmproxy-ca-cert.cer"
            certificate.write_bytes(b"fake-der-certificate")

            open_store = mock.MagicMock(return_value=123)
            add_certificate = mock.MagicMock(return_value=1)
            close_store = mock.MagicMock(return_value=1)
            crypt32 = SimpleNamespace(
                CertOpenStore=open_store,
                CertAddEncodedCertificateToStore=add_certificate,
                CertCloseStore=close_store,
            )
            with (
                mock.patch.object(nct_runtime.sys, "platform", "win32"),
                mock.patch.object(elevation, "is_elevated", return_value=True),
                mock.patch.object(nct_runtime.ctypes, "WinDLL", return_value=crypt32, create=True) as win_dll,
            ):
                nct_runtime.add_certificate_to_local_machine_root(certificate)

            win_dll.assert_called_once_with("crypt32", use_last_error=True)
            self.assertEqual(open_store.call_count, 1)
            self.assertEqual(open_store.call_args.args[3], 0x00020000 | 0x00004000)
            self.assertEqual(add_certificate.call_count, 1)
            self.assertEqual(add_certificate.call_args.args[0], 123)
            self.assertEqual(add_certificate.call_args.args[3], len(b"fake-der-certificate"))
            self.assertEqual(add_certificate.call_args.args[4], 3)
            close_store.assert_called_once_with(123, 0)

    def test_already_trusted_certificate_is_silent_and_not_reinstalled(self) -> None:
        certificate = Path("C:/Users/Test/AppData/Local/DarkLotus/Ninja Capture Tool/mitmproxy/mitmproxy-ca-cert.cer")
        with (
            mock.patch.object(nct_runtime, "mitmproxy_ca_trust_status", return_value=("trusted", certificate)),
            mock.patch.object(nct_runtime.subprocess, "run") as run,
        ):
            self.assertFalse(nct_runtime.ensure_mitmproxy_ca_trusted())
        run.assert_not_called()

    def test_certificate_trust_preflight_checks_user_and_machine_root_stores_without_certutil(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            confdir = Path(tmp)
            certificate = confdir / "mitmproxy-ca-cert.cer"
            certificate.write_bytes(b"fake-der-certificate")
            (confdir / "mitmproxy-ca.pem").write_bytes(b"fake-der-certificate")
            with (
                mock.patch.object(nct_runtime.sys, "platform", "win32"),
                mock.patch.object(common, "mitmproxy_conf_directory", return_value=confdir),
                mock.patch.object(nct_runtime, "_certificate_is_trusted_in_root_store", side_effect=[False, True]) as trusted,
                mock.patch.object(nct_runtime.subprocess, "run") as run,
            ):
                status, found = nct_runtime.mitmproxy_ca_trust_status()
            self.assertEqual((status, found), ("trusted", certificate))
            self.assertEqual(
                [call.args[1] for call in trusted.call_args_list],
                [0x00010000, 0x00020000],
            )
            run.assert_not_called()

    def test_missing_certificate_is_generated_before_trust_installation(self) -> None:
        certificate = Path("C:/Users/Test/AppData/Local/DarkLotus/Ninja Capture Tool/mitmproxy/mitmproxy-ca-cert.cer")
        with (
            mock.patch.object(nct_runtime, "mitmproxy_ca_trust_status", side_effect=[("missing", None), ("untrusted", certificate), ("trusted", certificate)]),
            mock.patch.object(nct_runtime, "ensure_mitmproxy_ca_exists", return_value=certificate) as ensure_ca,
            mock.patch.object(elevation, "is_elevated", return_value=True),
            mock.patch.object(nct_runtime, "add_certificate_to_local_machine_root") as install_certificate,
        ):
            self.assertTrue(nct_runtime.ensure_mitmproxy_ca_trusted())
        ensure_ca.assert_called_once_with()
        install_certificate.assert_called_once_with(certificate)

    def test_frozen_capture_smoke_test_sets_capture_mode(self) -> None:
        completed = SimpleNamespace(returncode=0, stdout="", stderr="")
        with mock.patch.object(build_release, "_run_tracked_build_process", return_value=completed) as run:
            build_release.smoke_test_frozen_capture(Path("NinjaCaptureTool.exe"))
        environment = run.call_args.kwargs["env"]
        self.assertEqual(environment["NCT_SMOKE_TEST"], "frozen-capture")
        self.assertNotIn("PYINSTALLER_STRICT_UNPACK_MODE", environment)

    def test_requirements_pin_reproducible_runtime_dependencies(self) -> None:
        lines = (build_release.ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
        self.assertEqual(
            lines,
            [
                f"mitmproxy=={common.MITMPROXY_VERSION}",
                f"pysteam-client[client]=={common.STEAM_CLIENT_VERSION}",
            ],
        )

    def test_application_manifest_explicitly_runs_as_invoker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = build_release.create_application_manifest(Path(tmp))
            text = path.read_text(encoding="utf-8")
        self.assertIn('requestedExecutionLevel level="asInvoker" uiAccess="false"', text)
        self.assertIn("<longPathAware", text)

    def test_gevent_eventemitter_fallback_is_version_specific(self) -> None:
        distribution = mock.Mock()
        distribution.metadata = {"Name": "gevent-eventemitter"}
        distribution.version = "2.2"
        distribution.files = []
        self.assertEqual(build_release.fallback_license_files(distribution), [])

    def test_publicsuffix2_fallback_is_version_specific(self) -> None:
        distribution = mock.Mock()
        distribution.metadata = {"Name": "publicsuffix2"}
        distribution.version = "2.20191222"
        distribution.files = []
        self.assertEqual(build_release.fallback_license_files(distribution), [])

    def test_version_comparison_accepts_v_prefix_and_padding(self) -> None:
        self.assertEqual(common.compare_versions("v1.1.0", "1.1"), 0)
        self.assertGreater(common.compare_versions("1.2.0", "1.1.9"), 0)
        self.assertLess(common.compare_versions("1.0.9", "1.1.0"), 0)

    def test_installed_version_validation_is_headless(self) -> None:
        result = SimpleNamespace(returncode=0, stdout=f"Ninja Capture Tool v{common.display_version()}\n", stderr="")
        with mock.patch.object(update.subprocess, "run", return_value=result) as run:
            self.assertEqual(update._read_installed_version(Path("NinjaCaptureTool.exe"), Path(".")), common.display_version())
        self.assertNotIn("PYINSTALLER_RESET_ENVIRONMENT", run.call_args.kwargs["env"])
        self.assertEqual(run.call_args.kwargs["env"]["NCT_HEADLESS"], "1")
        self.assertEqual(run.call_args.kwargs["creationflags"], getattr(update.subprocess, "CREATE_NO_WINDOW", 0))
        self.assertEqual(run.call_args.kwargs["timeout"], 150)

    def test_capture_install_lock_uses_installation_scoped_filesystem_lock(self) -> None:
        observed: dict[str, object] = {}

        @contextlib.contextmanager
        def fake_file_lock(path, timeout_seconds, timeout_message):
            observed.update(path=path, timeout=timeout_seconds, message=timeout_message)
            yield

        with tempfile.TemporaryDirectory() as tmp:
            install = Path(tmp) / "install"
            local_root = Path(tmp) / "local" / "DarkLotus" / "Ninja Capture Tool"
            with (
                mock.patch.object(common, "nct_local_app_data_root", return_value=local_root),
                mock.patch.object(update, "nct_local_app_data_root", return_value=local_root, create=True),
                mock.patch.object(update, "capture_activity_lock_path", side_effect=common.capture_activity_lock_path),
                mock.patch.object(update, "windows_file_lock", side_effect=fake_file_lock),
            ):
                with update.capture_install_lock(install):
                    pass
                expected = common.capture_activity_lock_path(install)
        self.assertEqual(observed["timeout"], 0)
        self.assertEqual(observed["path"], expected)
        self.assertEqual(observed["message"], "Another Ninja Capture Tool capture is active.")

    def test_capture_install_lock_propagates_access_denied(self) -> None:
        denied = PermissionError(13, "Access denied")
        denied.winerror = 5
        with mock.patch.object(update, "windows_file_lock", side_effect=denied):
            with self.assertRaises(PermissionError):
                with update.capture_install_lock(Path("C:/NCT")):
                    pass

    def test_live_tracking_state_rejects_internally_impossible_combinations(self) -> None:
        base = {
            "high_water_version": "44.0",
            "high_water_observed_at": "2026-09-14T10:00:00+02:00",
            "last_valid_steam_manifest_id": 111,
            "last_valid_steam_manifest_size": 52 * 1024**3,
            "awaiting_content_branch": None,
            "awaiting_from_manifest_id": None,
            "pre_transition_manifest_id": None,
            "pre_transition_manifest_size": None,
            "pre_transition_content_branch": None,
        }
        invalid_states = [
            dict(base, last_valid_steam_manifest_id=None),
            dict(base, last_valid_steam_manifest_size=None),
            dict(base, last_valid_steam_manifest_size=1 * 1024**3),
            dict(base, awaiting_from_manifest_id=111),
            dict(base, awaiting_content_branch="43.5", awaiting_from_manifest_id=111),
            dict(
                base,
                pre_transition_manifest_id=222,
                pre_transition_manifest_size=53 * 1024**3,
                pre_transition_content_branch="43.5",
            ),
            dict(
                base,
                pre_transition_manifest_id=111,
                pre_transition_manifest_size=53 * 1024**3,
                pre_transition_content_branch="44.0",
            ),
            dict(
                base,
                awaiting_content_branch="44.0",
                awaiting_from_manifest_id=222,
                pre_transition_manifest_id=222,
                pre_transition_manifest_size=53 * 1024**3,
                pre_transition_content_branch="44.0",
            ),
            dict(
                base,
                awaiting_content_branch="44.0",
                awaiting_from_manifest_id=111,
                pre_transition_manifest_id=222,
                pre_transition_manifest_size=53 * 1024**3,
                pre_transition_content_branch="43.5",
            ),
            dict(
                base,
                awaiting_content_branch="44.0",
                awaiting_from_manifest_id=111,
                pre_transition_manifest_id=111,
                pre_transition_manifest_size=52 * 1024**3,
                pre_transition_content_branch="45.0",
            ),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "warframe_version.json"
            for state in invalid_states:
                with self.subTest(state=state):
                    common.atomic_write_json(path, state)
                    with self.assertRaises(RuntimeError):
                        steam_tracking.load_live_tracking_state(path)

    def test_certificate_trust_probe_accepts_other_store_when_one_store_is_unreadable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            confdir = Path(tmp)
            certificate = confdir / "mitmproxy-ca-cert.cer"
            certificate.write_bytes(b"fake-der-certificate")
            (confdir / "mitmproxy-ca.pem").write_bytes(b"fake-der-certificate")
            with (
                mock.patch.object(nct_runtime.sys, "platform", "win32"),
                mock.patch.object(common, "mitmproxy_conf_directory", return_value=confdir),
                mock.patch.object(
                    nct_runtime,
                    "_certificate_is_trusted_in_root_store",
                    side_effect=[OSError("current-user root unavailable"), True],
                ) as trusted,
            ):
                self.assertEqual(nct_runtime.mitmproxy_ca_trust_status(), ("trusted", certificate))
            self.assertEqual(
                [call.args[1] for call in trusted.call_args_list],
                [0x00010000, 0x00020000],
            )

    def test_certificate_trust_probe_reports_unknown_when_one_store_cannot_be_checked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            confdir = Path(tmp)
            certificate = confdir / "mitmproxy-ca-cert.cer"
            certificate.write_bytes(b"fake-der-certificate")
            (confdir / "mitmproxy-ca.pem").write_bytes(b"fake-der-certificate")
            with (
                mock.patch.object(nct_runtime.sys, "platform", "win32"),
                mock.patch.object(common, "mitmproxy_conf_directory", return_value=confdir),
                mock.patch.object(
                    nct_runtime,
                    "_certificate_is_trusted_in_root_store",
                    side_effect=[False, OSError("machine root unavailable")],
                ),
            ):
                self.assertEqual(nct_runtime.mitmproxy_ca_trust_status(), ("unknown", certificate))

    def test_unknown_certificate_trust_never_installs_blindly(self) -> None:
        certificate = Path("C:/Users/Test/AppData/Local/DarkLotus/Ninja Capture Tool/mitmproxy/mitmproxy-ca-cert.cer")
        with (
            mock.patch.object(nct_runtime, "mitmproxy_ca_trust_status", return_value=("unknown", certificate)),
            mock.patch.object(elevation, "is_elevated", return_value=True),
            mock.patch.object(nct_runtime, "add_certificate_to_local_machine_root") as install_certificate,
        ):
            with self.assertRaisesRegex(RuntimeError, "Could not determine whether .* HTTPS certificate is trusted"):
                nct_runtime.ensure_mitmproxy_ca_trusted()
        install_certificate.assert_not_called()

    def test_post_install_unknown_trust_reports_verification_failure(self) -> None:
        certificate = Path("C:/Users/Test/AppData/Local/DarkLotus/Ninja Capture Tool/mitmproxy/mitmproxy-ca-cert.cer")
        with (
            mock.patch.object(
                nct_runtime,
                "mitmproxy_ca_trust_status",
                side_effect=[("untrusted", certificate), ("unknown", certificate)],
            ),
            mock.patch.object(elevation, "is_elevated", return_value=True),
            mock.patch.object(nct_runtime, "add_certificate_to_local_machine_root") as install_certificate,
        ):
            with self.assertRaisesRegex(RuntimeError, "installed its HTTPS certificate, but Windows trust could not be verified"):
                nct_runtime.ensure_mitmproxy_ca_trusted()
        install_certificate.assert_called_once_with(certificate)

    def test_certificate_removal_uses_exact_hash_match_in_requested_root_store(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            certificate = Path(tmp) / "mitmproxy-ca-cert.cer"
            certificate.write_bytes(b"fake-der-certificate")
            open_store = mock.MagicMock(return_value=123)
            find_certificate = mock.MagicMock(return_value=456)
            delete_certificate = mock.MagicMock(return_value=1)
            close_store = mock.MagicMock(return_value=1)
            crypt32 = SimpleNamespace(
                CertOpenStore=open_store,
                CertFindCertificateInStore=find_certificate,
                CertDeleteCertificateFromStore=delete_certificate,
                CertCloseStore=close_store,
            )
            with mock.patch.object(nct_runtime.ctypes, "WinDLL", return_value=crypt32, create=True):
                self.assertTrue(nct_runtime._remove_certificate_from_root_store(certificate, 0x00020000))
            self.assertEqual(open_store.call_args.args[3], 0x00020000 | 0x00004000)
            self.assertEqual(find_certificate.call_args.args[3], 0x00010000)
            delete_certificate.assert_called_once_with(456)
            close_store.assert_called_once_with(123, 0)

    def test_remove_shared_ca_removes_both_root_store_matches_then_shared_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            confdir = Path(tmp) / "mitmproxy"
            confdir.mkdir()
            certificate = confdir / "mitmproxy-ca-cert.cer"
            certificate.write_bytes(b"fake-der-certificate")
            (confdir / "mitmproxy-ca.pem").write_bytes(b"fake-der-certificate")
            with (
                mock.patch.object(nct_runtime.sys, "platform", "win32"),
                mock.patch.object(elevation, "is_elevated", return_value=True),
                mock.patch.object(common, "mitmproxy_conf_directory", return_value=confdir),
                mock.patch.object(
                    nct_runtime,
                    "_remove_certificate_from_root_store",
                    side_effect=[True, False],
                ) as remove_from_store,
            ):
                self.assertEqual(nct_runtime.remove_mitmproxy_ca(), (1, True))
            self.assertEqual(
                [call.args[1] for call in remove_from_store.call_args_list],
                [0x00010000, 0x00020000],
            )
            self.assertFalse(confdir.exists())

    def test_remove_shared_ca_removes_each_exact_identity_when_public_and_private_ca_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            confdir = Path(tmp) / "mitmproxy"
            confdir.mkdir()
            certificate = confdir / "mitmproxy-ca-cert.cer"
            certificate.write_bytes(b"public-ca-a")
            private_ca = confdir / "mitmproxy-ca.pem"
            private_ca.write_bytes(b"private-ca-b")
            with (
                mock.patch.object(nct_runtime.sys, "platform", "win32"),
                mock.patch.object(elevation, "is_elevated", return_value=True),
                mock.patch.object(common, "mitmproxy_conf_directory", return_value=confdir),
                mock.patch.object(
                    nct_runtime,
                    "_remove_certificate_from_root_store",
                    side_effect=[True, False, False, True],
                ) as remove_from_store,
            ):
                self.assertEqual(nct_runtime.remove_mitmproxy_ca(), (2, True))
            self.assertEqual(
                [(call.args[0], call.args[1]) for call in remove_from_store.call_args_list],
                [
                    (certificate, 0x00010000),
                    (certificate, 0x00020000),
                    (private_ca, 0x00010000),
                    (private_ca, 0x00020000),
                ],
            )
            self.assertFalse(confdir.exists())

    def test_remove_shared_ca_attempts_every_store_and_keeps_files_after_partial_store_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            confdir = Path(tmp) / "mitmproxy"
            confdir.mkdir()
            certificate = confdir / "mitmproxy-ca-cert.cer"
            certificate.write_bytes(b"public-ca-a")
            private_ca = confdir / "mitmproxy-ca.pem"
            private_ca.write_bytes(b"private-ca-b")
            with (
                mock.patch.object(nct_runtime.sys, "platform", "win32"),
                mock.patch.object(elevation, "is_elevated", return_value=True),
                mock.patch.object(common, "mitmproxy_conf_directory", return_value=confdir),
                mock.patch.object(
                    nct_runtime,
                    "_remove_certificate_from_root_store",
                    side_effect=[OSError("current-user unavailable"), True, False, True],
                ) as remove_from_store,
            ):
                with self.assertRaisesRegex(RuntimeError, "could not fully inspect/remove") as raised:
                    nct_runtime.remove_mitmproxy_ca()
            self.assertEqual(remove_from_store.call_count, 4)
            self.assertIn("Current User Root", str(raised.exception))
            self.assertIn("Retry --remove-https-certificate", str(raised.exception))
            self.assertTrue(confdir.exists())
            self.assertTrue(certificate.exists())
            self.assertTrue(private_ca.exists())

    def test_remove_shared_ca_falls_back_to_private_ca_when_exported_certificate_is_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            confdir = Path(tmp) / "mitmproxy"
            confdir.mkdir()
            exported = confdir / "mitmproxy-ca-cert.cer"
            exported.write_bytes(b"")
            private_ca = confdir / "mitmproxy-ca.pem"
            private_ca.write_bytes(b"private-ca-with-certificate")
            with (
                mock.patch.object(nct_runtime.sys, "platform", "win32"),
                mock.patch.object(elevation, "is_elevated", return_value=True),
                mock.patch.object(common, "mitmproxy_conf_directory", return_value=confdir),
                mock.patch.object(nct_runtime, "_remove_certificate_from_root_store", return_value=False) as remove_from_store,
            ):
                self.assertEqual(nct_runtime.remove_mitmproxy_ca(), (0, True))
            self.assertTrue(all(call.args[0] == private_ca for call in remove_from_store.call_args_list))
            self.assertFalse(confdir.exists())
