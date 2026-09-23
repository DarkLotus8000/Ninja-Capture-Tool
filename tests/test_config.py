# Run from the project root with: py -B -m unittest discover -s tests
from support import *

class ConfigTests(NctTestBase):
    def test_display_version_hides_zero_patch_component(self) -> None:
        self.assertEqual(common.display_version("1.0.0"), "1.0")
        self.assertEqual(common.display_version("1.5.0"), "1.5")
        self.assertEqual(common.display_version("1.0.1"), "1.0.1")
        self.assertEqual(common.display_version("1.5"), "1.5")

    def test_argument_parser_colors_startup_error_prefix_on_tty(self) -> None:
        stderr = io.StringIO()
        parser = nct_config.build_argument_parser()
        with (
            mock.patch.object(common, "console_supports_color", return_value=True),
            contextlib.redirect_stderr(stderr),
            self.assertRaises(SystemExit),
        ):
            parser.parse_args(["--definitely-invalid"])
        self.assertIn("\x1b[31mERROR:\x1b[0m", stderr.getvalue())

    def test_argument_parser_capitalizes_generated_error_message(self) -> None:
        stderr = io.StringIO()
        parser = nct_config.build_argument_parser()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            parser.parse_args(["--definitely-invalid"])
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("ERROR: Unrecognized arguments: --definitely-invalid", stderr.getvalue())

    def test_argument_parser_uses_unindented_continuation_lines_for_usage(self) -> None:
        parser = nct_config.build_argument_parser()
        parser.prog = "NinjaCaptureTool.exe"
        lines = parser.format_usage().splitlines()
        self.assertGreater(len(lines), 1)
        self.assertTrue(lines[0].startswith("usage: NinjaCaptureTool.exe "))
        self.assertTrue(all(line == line.lstrip() for line in lines[1:] if line))

    def test_argument_parser_help_uses_compact_consistent_layout(self) -> None:
        parser = nct_config.build_argument_parser()
        parser.prog = "NinjaCaptureTool.exe"
        help_text = parser.format_help()
        lines = help_text.splitlines()
        normalized_help = " ".join(line.strip() for line in lines)
        self.assertIn("Capture Warframe CDN responses for OpenWF.", normalized_help)
        self.assertNotIn("content.warframe.com", normalized_help)
        certificate_line = next(line for line in lines if "-C, --remove-https-certificate" in line)
        self.assertIn("Remove Ninja Capture Tool's HTTPS", certificate_line)
        delay_line = next(line for line in lines if "-w, --stop-on-exit-delay SECONDS" in line)
        self.assertIn("Seconds selected processes", delay_line)
        self.assertIn("-v, --version", help_text)
        self.assertIn("Shows the Ninja Capture Tool version", normalized_help)
        self.assertIn("-h, --help", help_text)
        self.assertIn("Shows this help message", normalized_help)
        self.assertNotIn("NCT", normalized_help)
        self.assertNotIn("show this help message and exit", help_text)
        self.assertNotIn("show program's version number and exit", help_text)
        option_lines = [line.strip() for line in lines if line.startswith("  -")]
        option_index = lambda prefix: next(index for index, line in enumerate(option_lines) if line.startswith(prefix))
        self.assertLess(option_index("-r, --remove-elevation-task"), option_index("-a, --auto-update"))
        self.assertLess(option_index("-U, --check-update"), option_index("-v, --version"))
        self.assertLess(option_index("-v, --version"), option_index("-h, --help"))
        self.assertNotIn("\n\n\n", help_text)

    def test_argument_parser_shows_console_before_reporting_error(self) -> None:
        stderr = io.StringIO()
        parser = nct_config.build_argument_parser()
        with (
            mock.patch.object(nct_runtime, "show_console_window") as show_console,
            contextlib.redirect_stderr(stderr),
            self.assertRaises(SystemExit) as raised,
        ):
            parser.parse_args(["--definitely-invalid"])
        self.assertEqual(raised.exception.code, 2)
        show_console.assert_called_once_with()
        self.assertIn("ERROR: Unrecognized arguments: --definitely-invalid", stderr.getvalue())

    def test_main_unknown_argument_shows_console_once_before_argparse_error(self) -> None:
        stderr = io.StringIO()
        with (
            mock.patch.object(nct.sys, "platform", "win32"),
            mock.patch.object(nct, "handle_early_update_request", return_value=None),
            mock.patch.object(nct_runtime, "show_console_window") as show_console,
            contextlib.redirect_stderr(stderr),
            self.assertRaises(SystemExit) as raised,
        ):
            nct.main(["-x"])
        self.assertEqual(raised.exception.code, 2)
        show_console.assert_called_once_with()
        self.assertIn("ERROR: Unrecognized arguments: -x", stderr.getvalue())

    def test_argument_parser_preserves_option_leading_error_message(self) -> None:
        stderr = io.StringIO()
        parser = nct_config.build_argument_parser()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            parser.error("--check-update must be used without operation arguments")
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("ERROR: --check-update must be used without operation arguments", stderr.getvalue())

    def test_session_naming_cli_options_are_mutually_exclusive_and_use_red_error_prefix(self) -> None:
        stderr = io.StringIO()
        parser = nct_config.build_argument_parser()
        with (
            mock.patch.object(common, "console_supports_color", return_value=True),
            contextlib.redirect_stderr(stderr),
            self.assertRaises(SystemExit),
        ):
            parser.parse_args(["--output", "custom-session", "--version-session-name"])
        error = stderr.getvalue()
        self.assertIn("\x1b[31mERROR:\x1b[0m", error)
        self.assertIn("--output", error)
        self.assertIn("--version-session-name", error)

    def test_config_signature_detects_same_size_same_mtime_content_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_bytes(b"AAAA")
            original = path.stat()
            first = nct_config.config_file_signature(path)

            path.write_bytes(b"BBBB")
            os.utime(path, ns=(original.st_atime_ns, original.st_mtime_ns))

            self.assertEqual(path.stat().st_size, original.st_size)
            self.assertEqual(path.stat().st_mtime_ns, original.st_mtime_ns)
            self.assertNotEqual(nct_config.config_file_signature(path), first)

    def test_startup_config_snapshot_retries_until_loaded_content_is_stable(self) -> None:
        second = dict(nct_config.DEFAULT_CONFIG)
        second["stop_on_exit_delay"] = 20
        with (
            mock.patch.object(
                nct_config,
                "load_exact_config_snapshot",
                side_effect=[nct_config.ConfigSnapshotChanged(), (second, "b")],
            ) as load_snapshot,
            mock.patch.object(nct.time, "sleep") as sleep,
        ):
            config, signature = nct_config.load_stable_config_snapshot(Path("config.json"))

        self.assertEqual(config, second)
        self.assertEqual(signature, "b")
        self.assertEqual(load_snapshot.call_count, 2)
        sleep.assert_called_once_with(0.025)

    def test_exact_config_snapshot_never_pairs_parsed_bytes_with_another_signature(self) -> None:
        config_b = dict(nct_config.DEFAULT_CONFIG)
        config_b["stop_on_exit_delay"] = 20
        data_b = (json.dumps(config_b) + "\n").encode("utf-8")
        signature_a = hashlib.sha256(b"config-a").hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_bytes(data_b)
            with (
                mock.patch.object(Path, "read_bytes", return_value=data_b),
                mock.patch.object(nct_config, "config_file_signature", return_value=signature_a),
                mock.patch.object(nct_config, "load_config_content") as parse_content,
                self.assertRaises(nct_config.ConfigSnapshotChanged),
            ):
                nct_config.load_exact_config_snapshot(path)
        parse_content.assert_not_called()

    def test_exact_config_snapshot_hashes_and_parses_the_same_bytes(self) -> None:
        config = dict(nct_config.DEFAULT_CONFIG)
        config["stop_on_exit_delay"] = 20
        data = (json.dumps(config) + "\n").encode("utf-8")
        signature = hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_bytes(data)
            with mock.patch.object(nct_config, "config_file_signature", return_value=signature):
                loaded, loaded_signature = nct_config.load_exact_config_snapshot(path)
        self.assertEqual(loaded["stop_on_exit_delay"], 20)
        self.assertEqual(loaded_signature, signature)

    def test_startup_waits_for_invalid_config_then_continues_after_stable_fix(self) -> None:
        args = nct_config.build_argument_parser().parse_args([])
        valid_config = dict(nct_config.DEFAULT_CONFIG)
        valid_options = nct_config.resolve_runtime_options(args, valid_config)
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(
                nct_config,
                "load_stable_config_snapshot",
                side_effect=[
                    RuntimeError('config.json "capture_mode" must be "local" or "system-proxy".'),
                    (valid_config, "good"),
                ],
            ),
            mock.patch.object(nct_config, "resolve_runtime_options", return_value=valid_options) as resolve,
            mock.patch.object(nct_config, "config_file_signature", side_effect=["bad", "good", "good"]),
            mock.patch.object(nct.time, "monotonic", side_effect=[0.0, 1.0, 1.6]),
            mock.patch.object(nct.time, "sleep"),
            mock.patch.object(nct_runtime, "show_console_window") as show_console,
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            config, signature, options = nct._load_startup_config_and_options(args)

        self.assertEqual(config, valid_config)
        self.assertEqual(signature, "good")
        self.assertEqual(options, valid_options)
        resolve.assert_called_once_with(args, valid_config)
        show_console.assert_called_once_with()
        self.assertIn('capture_mode" must be "local" or "system-proxy"', stderr.getvalue())
        self.assertIn("Startup is paused until config.json is valid", stdout.getvalue())
        self.assertIn("Configuration is valid. Continuing startup.", stdout.getvalue())

    def test_startup_prints_each_independent_config_error(self) -> None:
        args = nct_config.build_argument_parser().parse_args([])
        valid_config = dict(nct_config.DEFAULT_CONFIG)
        valid_options = nct_config.resolve_runtime_options(args, valid_config)
        stdout = io.StringIO()
        stderr = io.StringIO()
        problems = nct_config.ConfigValidationError(
            [
                'config.json "capture_mode" must be "local" or "system-proxy".',
                'config.json "processes" must contain at least one executable.',
            ]
        )
        with (
            mock.patch.object(
                nct_config,
                "load_stable_config_snapshot",
                side_effect=[problems, (valid_config, "good")],
            ) as load_snapshot,
            mock.patch.object(nct_config, "resolve_runtime_options", return_value=valid_options),
            mock.patch.object(nct_config, "config_file_signature", side_effect=["bad", "good", "good"]),
            mock.patch.object(nct.time, "monotonic", side_effect=[0.0, 1.0, 1.6]),
            mock.patch.object(nct.time, "sleep"),
            mock.patch.object(nct_runtime, "show_console_window"),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            nct._load_startup_config_and_options(args)

        error_text = stderr.getvalue()
        self.assertEqual(error_text.count("ERROR:"), 2)
        self.assertIn('config.json "capture_mode" must be "local" or "system-proxy"', error_text)
        self.assertIn('config.json "processes" must contain at least one executable', error_text)
        self.assertEqual(load_snapshot.call_args_list[0].kwargs["allow_empty_processes"], False)
        self.assertIn("Startup is paused until config.json is valid", stdout.getvalue())

    def test_startup_allows_empty_config_processes_when_cli_processes_override_them(self) -> None:
        args = nct_config.build_argument_parser().parse_args(["--process", "Launcher.exe"])
        config = dict(nct_config.DEFAULT_CONFIG)
        config["processes"] = []
        options = nct_config.resolve_runtime_options(args, config)
        with (
            mock.patch.object(nct_config, "load_stable_config_snapshot", return_value=(config, "same")) as load_snapshot,
            mock.patch.object(nct_config, "config_file_signature", return_value="same"),
        ):
            loaded_config, signature, loaded_options = nct._load_startup_config_and_options(args)

        self.assertEqual(loaded_config, config)
        self.assertEqual(signature, "same")
        self.assertEqual(loaded_options, options)
        load_snapshot.assert_called_once_with(nct_config.CONFIG_FILE, allow_empty_processes=True)

    def test_startup_waits_for_invalid_config_combination_then_continues(self) -> None:
        args = nct_config.build_argument_parser().parse_args([])
        invalid_config = dict(nct_config.DEFAULT_CONFIG, capture_mode="system-proxy", debug="global")
        valid_config = dict(nct_config.DEFAULT_CONFIG)
        stderr = io.StringIO()
        with (
            mock.patch.object(
                nct_config,
                "load_stable_config_snapshot",
                side_effect=[(invalid_config, "bad"), (valid_config, "good")],
            ),
            mock.patch.object(nct_config, "config_file_signature", side_effect=["bad", "good", "good"]),
            mock.patch.object(nct.time, "monotonic", side_effect=[0.0, 1.0, 1.6]),
            mock.patch.object(nct.time, "sleep"),
            mock.patch.object(nct_runtime, "show_console_window"),
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(stderr),
        ):
            config, signature, options = nct._load_startup_config_and_options(args)

        self.assertEqual(config, valid_config)
        self.assertEqual(signature, "good")
        self.assertEqual(options["capture_mode"], "local")
        self.assertIn("Global debug requires Local Capture", stderr.getvalue())

    def test_startup_does_not_wait_for_incompatible_runtime_cli_overrides(self) -> None:
        args = nct_config.build_argument_parser().parse_args(["--capture-mode", "local", "--port", "8080"])
        config = dict(nct_config.DEFAULT_CONFIG)
        with (
            mock.patch.object(nct_config, "load_stable_config_snapshot", return_value=(config, "same")),
            mock.patch.object(nct_config, "config_file_signature", return_value="same"),
            mock.patch.object(nct.time, "monotonic", return_value=0.0),
            mock.patch.object(nct.time, "sleep") as sleep,
            mock.patch.object(nct_runtime, "show_console_window") as show_console,
        ):
            with self.assertRaisesRegex(RuntimeError, "--port can only be used with System Proxy mode"):
                nct._load_startup_config_and_options(args)

        sleep.assert_not_called()
        show_console.assert_not_called()

    def test_config_reload_uses_startup_snapshot_signature_as_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            startup = dict(nct_config.DEFAULT_CONFIG)
            common.atomic_write_json(path, startup)
            startup_signature = nct_config.config_file_signature(path)
            assert startup_signature is not None

            newer = dict(startup)
            newer["stop_on_exit_delay"] = 20
            common.atomic_write_json(path, newer)

            args = nct_config.build_argument_parser().parse_args([])
            options = nct_config.resolve_runtime_options(args, startup)
            session = nct.CaptureSession(options)
            session.enable_config_reload(args, path, initial_signature=startup_signature)

            self.assertEqual(session.config_signature, startup_signature)
            self.assertFalse(session._poll_config_reload(now=10.0))
            self.assertFalse(session._poll_config_reload(now=11.0))
            self.assertEqual(session.options["stop_on_exit_delay"], 20)

    def test_missing_config_is_created_with_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            config = nct_config.load_config(path)
            self.assertEqual(config, nct_config.DEFAULT_CONFIG)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), nct_config.DEFAULT_CONFIG)

    def test_shipped_config_matches_default_config(self) -> None:
        self.assertEqual(
            json.loads((Path(common.__file__).resolve().parent / "config.json").read_text(encoding="utf-8")),
            nct_config.DEFAULT_CONFIG,
        )

    def test_unknown_config_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text('{"wat": true}', encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "Unknown config option"):
                nct_config.load_config(path)

    def test_config_reserved_keywords_are_case_insensitive_and_canonicalized(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            config = dict(nct_config.DEFAULT_CONFIG)
            config.update({"capture_mode": " System-Proxy ", "debug": "GLOBAL", "upstream_proxy": "DiReCt"})
            path.write_text(json.dumps(config), encoding="utf-8")
            loaded = nct_config.load_config(path)
            self.assertEqual(loaded["capture_mode"], "system-proxy")
            self.assertEqual(loaded["debug"], "global")
            self.assertEqual(loaded["upstream_proxy"], "direct")

    def test_duplicate_config_processes_are_cleaned_without_collapsing_case_variants(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            config = dict(nct_config.DEFAULT_CONFIG)
            config.update({
                "processes": [
                    "Launcher.exe",
                    "launcher.exe",
                    "Launcher.exe",
                    "Warframe.x64.exe",
                    "Warframe.x64.exe",
                ],
                "upstream_proxy": "HTTP://User:PaSSword@ProxyHost:8080",
            })
            common.atomic_write_json(path, config)
            signature = nct_config.config_file_signature(path)
            assert signature is not None
            messages: list[str] = []

            duplicate_count, cleaned_signature = nct_config.clean_duplicate_config_processes(
                path,
                expected_signature=signature,
                emit=messages.append,
            )

            self.assertEqual(duplicate_count, 2)
            self.assertEqual(cleaned_signature, nct_config.config_file_signature(path))
            cleaned = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(
                cleaned["processes"],
                ["Launcher.exe", "launcher.exe", "Warframe.x64.exe"],
            )
            self.assertEqual(cleaned["upstream_proxy"], "HTTP://User:PaSSword@ProxyHost:8080")
            self.assertEqual(
                messages,
                [
                    "[Config] 2 duplicate process entries detected; cleaning config.json.",
                    "[Config] Removed 2 duplicate process entries from config.json.",
                ],
            )

    def test_duplicate_config_cleanup_does_not_overwrite_a_newer_edit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            config = dict(nct_config.DEFAULT_CONFIG)
            config["processes"] = ["Launcher.exe", "Launcher.exe"]
            common.atomic_write_json(path, config)
            original = path.read_bytes()
            signature = hashlib.sha256(original).hexdigest()
            newer = dict(config)
            newer["debug"] = True
            newer_bytes = (json.dumps(newer, indent=4, ensure_ascii=False) + "\n").encode("utf-8")
            messages: list[str] = []

            with mock.patch.object(Path, "read_bytes", side_effect=[original, newer_bytes]):
                duplicate_count, cleaned_signature = nct_config.clean_duplicate_config_processes(
                    path,
                    expected_signature=signature,
                    emit=messages.append,
                )

            self.assertEqual(duplicate_count, 1)
            self.assertIsNone(cleaned_signature)
            self.assertIn("leaving the newer file untouched", messages[-1])

    def test_cli_reserved_keywords_are_case_insensitive(self) -> None:
        parser = nct_config.build_argument_parser()
        mode_args = parser.parse_args(["--capture-mode", "System-Proxy", "--upstream-proxy", "DiReCt"])
        self.assertEqual(mode_args.capture_mode, "system-proxy")
        mode_options = nct_config.resolve_runtime_options(mode_args, dict(nct_config.DEFAULT_CONFIG))
        self.assertEqual(mode_options["upstream_proxy"], "direct")

        debug_args = parser.parse_args(["--debug", "Global"])
        self.assertEqual(debug_args.debug, "global")
        debug_options = nct_config.resolve_runtime_options(debug_args, dict(nct_config.DEFAULT_CONFIG))
        self.assertEqual(debug_options["debug"], "global")

    def test_invalid_config_values_are_reported_together(self) -> None:
        config = dict(nct_config.DEFAULT_CONFIG)
        config["capture_mode"] = "banana"
        config["processes"] = []
        config["proxy_port"] = 70000
        config["debug"] = "verbose"
        with self.assertRaises(nct_config.ConfigValidationError) as raised:
            nct_config.validate_config(config)
        self.assertEqual(
            raised.exception.messages,
            (
                'config.json "capture_mode" must be "local" or "system-proxy".',
                'config.json "processes" must contain at least one executable.',
                "config.json proxy_port must be a number from 1 to 65535.",
                'config.json debug must be true, false, or "global".',
            ),
        )

    def test_config_content_reports_unknown_and_invalid_known_fields_together(self) -> None:
        config = dict(nct_config.DEFAULT_CONFIG)
        config["capture_mode"] = "banana"
        config["wat"] = True
        with self.assertRaises(nct_config.ConfigValidationError) as raised:
            nct_config.load_config_content(json.dumps(config))
        self.assertEqual(
            raised.exception.messages,
            (
                "Unknown config option(s): wat",
                'config.json "capture_mode" must be "local" or "system-proxy".',
            ),
        )

    def test_invalid_config_values_are_rejected(self) -> None:
        for invalid_port in (70000, 8080.5, "8080", True):
            config = dict(nct_config.DEFAULT_CONFIG)
            config["proxy_port"] = invalid_port
            with self.assertRaisesRegex(RuntimeError, "number from 1 to 65535"):
                nct_config.validate_config(config)
        config = dict(nct_config.DEFAULT_CONFIG)
        config["processes"] = []
        with self.assertRaisesRegex(RuntimeError, "processes"):
            nct_config.validate_config(config)
        config = dict(nct_config.DEFAULT_CONFIG)
        config["capture_mode"] = "magic"
        with self.assertRaisesRegex(RuntimeError, "capture_mode"):
            nct_config.validate_config(config)
        config = dict(nct_config.DEFAULT_CONFIG)
        config["stop_on_exit"] = "yes"
        with self.assertRaisesRegex(RuntimeError, "stop_on_exit"):
            nct_config.validate_config(config)
        for invalid_delay in (0, -1, 15.5, "15", True):
            config = dict(nct_config.DEFAULT_CONFIG)
            config["stop_on_exit_delay"] = invalid_delay
            with self.assertRaisesRegex(RuntimeError, "number from 1 to 3600"):
                nct_config.validate_config(config)
        for invalid_interval in (0, -1, 0.5, 10**309):
            config = dict(nct_config.DEFAULT_CONFIG)
            config["live_check_interval_seconds"] = invalid_interval
            with self.assertRaisesRegex(RuntimeError, "positive number"):
                nct_config.validate_config(config)
        config = dict(nct_config.DEFAULT_CONFIG)
        config["live_check_interval_seconds"] = 86401
        nct_config.validate_config(config)
        config = dict(nct_config.DEFAULT_CONFIG)
        config["debug"] = "verbose"
        with self.assertRaisesRegex(RuntimeError, "debug"):
            nct_config.validate_config(config)
        config["debug"] = "global"
        nct_config.validate_config(config)
        config = dict(nct_config.DEFAULT_CONFIG)
        config["name_session_after_warframe_version"] = "yes"
        with self.assertRaisesRegex(RuntimeError, "name_session_after_warframe_version"):
            nct_config.validate_config(config)

    def test_live_config_reload_keeps_current_worker_when_process_monitor_blocks_local_restart(self) -> None:
        args = nct_config.build_argument_parser().parse_args([])
        options = dict(nct_config.DEFAULT_CONFIG)
        options["capture_mode"] = "system-proxy"
        session = nct.CaptureSession(options, cli_args=args)
        config = dict(nct_config.DEFAULT_CONFIG)
        output = io.StringIO()
        with (
            mock.patch.object(nct_runtime, "process_monitor_is_running", return_value=True),
            mock.patch.object(elevation, "is_elevated", return_value=True),
            mock.patch.object(session, "_restart_capture_subsystem") as restart_subsystem,
            contextlib.redirect_stdout(output),
        ):
            self.assertFalse(session._apply_reloaded_config(config))
        restart_subsystem.assert_not_called()
        self.assertEqual(session.options["capture_mode"], "system-proxy")
        self.assertIn(
            "[Config] Reload rejected: Process Monitor is running and is incompatible with Local Capture. "
            "Close Process Monitor and try again. Current runtime configuration unchanged.",
            output.getvalue(),
        )
        self.assertNotIn("[Config] Change detected.", output.getvalue())
        self.assertTrue(output.getvalue().endswith("\n\n"))

    def test_live_semantic_rejection_keeps_last_applied_config_signature(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            initial = dict(nct_config.DEFAULT_CONFIG)
            initial["capture_mode"] = "system-proxy"
            common.atomic_write_json(path, initial)
            args = nct_config.build_argument_parser().parse_args([])
            options = nct_config.resolve_runtime_options(args, initial)
            session = nct.CaptureSession(options)
            initial_signature = nct_config.config_file_signature(path)
            session.enable_config_reload(args, path, initial_signature=initial_signature)

            changed = dict(nct_config.DEFAULT_CONFIG)
            common.atomic_write_json(path, changed)
            changed_signature = nct_config.config_file_signature(path)
            output = io.StringIO()
            with (
                mock.patch.object(nct_runtime, "process_monitor_is_running", return_value=True),
                mock.patch.object(elevation, "is_elevated", return_value=True),
                contextlib.redirect_stdout(output),
            ):
                self.assertFalse(session._poll_config_reload(now=10.0))
                self.assertFalse(session._poll_config_reload(now=11.0))
                # The same rejected bytes are remembered and not retried/spammed.
                self.assertFalse(session._poll_config_reload(now=12.0))

            self.assertEqual(session.options["capture_mode"], "system-proxy")
            self.assertEqual(session.config_signature, initial_signature)
            self.assertTrue(session.config_rejected_signature_set)
            self.assertEqual(session.config_rejected_signature, changed_signature)
            self.assertEqual(output.getvalue().count("[Config] Reload rejected:"), 1)

    def test_runtime_options_report_empty_process_list_as_fatal_configuration_error(self) -> None:
        args = nct_config.build_argument_parser().parse_args([])
        config = dict(nct_config.DEFAULT_CONFIG)
        config["processes"] = []
        with self.assertRaisesRegex(RuntimeError, "No capture processes configured"):
            nct_config.resolve_runtime_options(args, config)

    def test_live_cli_pinned_processes_ignore_config_process_changes_silently(self) -> None:
        args = nct_config.build_argument_parser().parse_args(["--process", "Launcher.exe"])
        options = nct_config.resolve_runtime_options(args, dict(nct_config.DEFAULT_CONFIG))
        session = nct.CaptureSession(options, cli_args=args)
        config = dict(nct_config.DEFAULT_CONFIG)
        config["processes"] = []
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertFalse(session._apply_reloaded_config(config))
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(session.options["processes"], ["Launcher.exe"])

    def test_live_cli_pinned_debug_ignores_config_debug_changes_silently(self) -> None:
        args = nct_config.build_argument_parser().parse_args(["--debug", "global"])
        options = nct_config.resolve_runtime_options(args, dict(nct_config.DEFAULT_CONFIG))
        session = nct.CaptureSession(options, cli_args=args)
        config = dict(nct_config.DEFAULT_CONFIG)
        config["debug"] = True
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertFalse(session._apply_reloaded_config(config))
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(session.options["debug"], "global")

    def test_live_cli_process_override_does_not_pin_capture_mode(self) -> None:
        args = nct_config.build_argument_parser().parse_args(["--process", "Launcher.exe"])
        options = nct_config.resolve_runtime_options(args, dict(nct_config.DEFAULT_CONFIG))
        session = nct.CaptureSession(options, cli_args=args)

        def apply_restart(new_options: dict[str, object]) -> None:
            session.options = dict(new_options)
            session.proxy_port = int(new_options["proxy_port"])

        system_proxy = dict(nct_config.DEFAULT_CONFIG, capture_mode="system-proxy", processes=[])
        local = dict(nct_config.DEFAULT_CONFIG, processes=[])
        with (
            mock.patch.object(session, "_restart_capture_subsystem", side_effect=apply_restart) as restart_subsystem,
            mock.patch.object(nct_runtime, "set_console_title"),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertFalse(session._apply_reloaded_config(system_proxy))
            self.assertEqual(session.options["capture_mode"], "system-proxy")
            self.assertEqual(session.options["processes"], ["Launcher.exe"])
            self.assertFalse(session._apply_reloaded_config(local))

        self.assertEqual(restart_subsystem.call_count, 2)
        self.assertEqual(session.options["capture_mode"], "local")
        self.assertEqual(session.options["processes"], ["Launcher.exe"])

    def test_live_cli_global_debug_override_is_dormant_in_system_proxy(self) -> None:
        args = nct_config.build_argument_parser().parse_args(["--debug", "global"])
        options = nct_config.resolve_runtime_options(args, dict(nct_config.DEFAULT_CONFIG))
        session = nct.CaptureSession(options, cli_args=args)

        def apply_restart(new_options: dict[str, object]) -> None:
            session.options = dict(new_options)
            session.proxy_port = int(new_options["proxy_port"])

        system_proxy = dict(nct_config.DEFAULT_CONFIG, capture_mode="system-proxy", debug=False)
        local = dict(nct_config.DEFAULT_CONFIG, debug=False)
        with (
            mock.patch.object(session, "_restart_capture_subsystem", side_effect=apply_restart),
            mock.patch.object(nct_runtime, "set_console_title"),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertFalse(session._apply_reloaded_config(system_proxy))
            self.assertEqual(session.options["capture_mode"], "system-proxy")
            self.assertFalse(session.options["debug"])
            self.assertFalse(session._apply_reloaded_config(local))

        self.assertEqual(session.options["capture_mode"], "local")
        self.assertEqual(session.options["debug"], "global")

    def test_live_invalid_json_keeps_current_configuration_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            common.atomic_write_json(path, nct_config.DEFAULT_CONFIG)
            args = nct_config.build_argument_parser().parse_args([])
            options = nct_config.resolve_runtime_options(args, dict(nct_config.DEFAULT_CONFIG))
            session = nct.CaptureSession(options)
            session.enable_config_reload(args, path)
            original_options = dict(session.options)
            path.write_text('{"debug":', encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertFalse(session._poll_config_reload(now=10.0))
                self.assertFalse(session._poll_config_reload(now=11.0))
            self.assertEqual(session.options, original_options)
            text = output.getvalue()
            self.assertIn("[Config] Reload rejected: invalid JSON:", text)
            self.assertIn("Current runtime configuration unchanged.", text)

    def test_live_temporarily_missing_config_keeps_current_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            common.atomic_write_json(path, nct_config.DEFAULT_CONFIG)
            args = nct_config.build_argument_parser().parse_args([])
            options = nct_config.resolve_runtime_options(args, dict(nct_config.DEFAULT_CONFIG))
            session = nct.CaptureSession(options)
            session.enable_config_reload(args, path)
            original_options = dict(session.options)
            path.unlink()
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertFalse(session._poll_config_reload(now=30.0))
                self.assertFalse(session._poll_config_reload(now=31.0))
            self.assertEqual(session.options, original_options)
            self.assertIn(
                "[Config] Reload rejected: config.json is missing. Current runtime configuration unchanged.",
                output.getvalue(),
            )

    def test_live_persistent_missing_config_reports_only_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            common.atomic_write_json(path, nct_config.DEFAULT_CONFIG)
            args = nct_config.build_argument_parser().parse_args([])
            options = nct_config.resolve_runtime_options(args, dict(nct_config.DEFAULT_CONFIG))
            session = nct.CaptureSession(options)
            session.enable_config_reload(args, path)
            path.unlink()

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertFalse(session._poll_config_reload(now=20.0))
                self.assertFalse(session._poll_config_reload(now=21.0))
                self.assertFalse(session._poll_config_reload(now=22.0))
                self.assertFalse(session._poll_config_reload(now=23.0))

            self.assertEqual(
                output.getvalue().count(
                    "[Config] Reload rejected: config.json is missing. Current runtime configuration unchanged."
                ),
                1,
            )
            self.assertTrue(session.config_rejected_signature_set)
            self.assertIsNone(session.config_rejected_signature)

    def test_live_editing_rejected_config_causes_new_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            common.atomic_write_json(path, nct_config.DEFAULT_CONFIG)
            args = nct_config.build_argument_parser().parse_args([])
            options = nct_config.resolve_runtime_options(args, dict(nct_config.DEFAULT_CONFIG))
            session = nct.CaptureSession(options)
            session.enable_config_reload(args, path)

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                path.write_text('{"debug":', encoding="utf-8")
                self.assertFalse(session._poll_config_reload(now=30.0))
                self.assertFalse(session._poll_config_reload(now=31.0))

                path.write_text('{"debug": tru', encoding="utf-8")
                self.assertFalse(session._poll_config_reload(now=32.0))
                self.assertFalse(session._poll_config_reload(now=33.0))

            self.assertEqual(output.getvalue().count("[Config] Reload rejected: invalid JSON:"), 2)

    def test_live_fixing_rejected_config_applies_normally(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            common.atomic_write_json(path, nct_config.DEFAULT_CONFIG)
            args = nct_config.build_argument_parser().parse_args([])
            options = nct_config.resolve_runtime_options(args, dict(nct_config.DEFAULT_CONFIG))
            session = nct.CaptureSession(options)
            session.enable_config_reload(args, path)

            def apply_worker(new_options):
                session.options = dict(new_options)

            output = io.StringIO()
            with (
                mock.patch.object(session, "_drain_worker_before_restart"),
                mock.patch.object(session, "_restart_worker_for_options", side_effect=apply_worker) as restart_worker,
                contextlib.redirect_stdout(output),
            ):
                path.write_text('{"debug":', encoding="utf-8")
                self.assertFalse(session._poll_config_reload(now=40.0))
                self.assertFalse(session._poll_config_reload(now=41.0))

                fixed = dict(nct_config.DEFAULT_CONFIG)
                fixed["debug"] = True
                common.atomic_write_json(path, fixed)
                self.assertFalse(session._poll_config_reload(now=42.0))
                self.assertFalse(session._poll_config_reload(now=43.0))

            restart_worker.assert_called_once()
            self.assertEqual(session.options["debug"], True)
            self.assertIn("[Config] Change detected.", output.getvalue())
            self.assertNotIn("Configuration is valid again", output.getvalue())
            self.assertFalse(session.config_rejected_signature_set)
            self.assertIsNone(session.config_rejected_signature)

    def test_live_fixing_rejected_config_back_to_active_snapshot_reports_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            common.atomic_write_json(path, nct_config.DEFAULT_CONFIG)
            args = nct_config.build_argument_parser().parse_args([])
            options = nct_config.resolve_runtime_options(args, dict(nct_config.DEFAULT_CONFIG))
            session = nct.CaptureSession(options)
            session.enable_config_reload(args, path)

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                path.write_text('{"debug":', encoding="utf-8")
                self.assertFalse(session._poll_config_reload(now=50.0))
                self.assertFalse(session._poll_config_reload(now=51.0))

                common.atomic_write_json(path, nct_config.DEFAULT_CONFIG)
                self.assertFalse(session._poll_config_reload(now=52.0))

            text = output.getvalue()
            self.assertEqual(text.count("[Config] Reload rejected:"), 1)
            self.assertEqual(
                text.count("[Config] Configuration is valid again. Current runtime configuration unchanged."),
                1,
            )
            self.assertFalse(session.config_rejected_signature_set)
            self.assertIsNone(session.config_rejected_signature)

    def test_live_fixing_rejected_config_to_equivalent_snapshot_reports_recovery_after_debounce(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            common.atomic_write_json(path, nct_config.DEFAULT_CONFIG)
            args = nct_config.build_argument_parser().parse_args([])
            options = nct_config.resolve_runtime_options(args, dict(nct_config.DEFAULT_CONFIG))
            session = nct.CaptureSession(options)
            session.enable_config_reload(args, path)

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                path.write_text('{"debug":', encoding="utf-8")
                self.assertFalse(session._poll_config_reload(now=60.0))
                self.assertFalse(session._poll_config_reload(now=61.0))

                # Same effective values as the active runtime, but deliberately
                # different bytes from the last accepted config snapshot.
                path.write_text(json.dumps(nct_config.DEFAULT_CONFIG, separators=(",", ":")), encoding="utf-8")
                self.assertFalse(session._poll_config_reload(now=62.0))
                self.assertFalse(session._poll_config_reload(now=63.0))

            text = output.getvalue()
            self.assertEqual(
                text.count("[Config] Configuration is valid again. Current runtime configuration unchanged."),
                1,
            )
            self.assertNotIn("[Config] Change detected.", text)
            self.assertFalse(session.config_rejected_signature_set)
            self.assertIsNone(session.config_rejected_signature)

    def test_live_empty_process_array_keeps_current_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            common.atomic_write_json(path, nct_config.DEFAULT_CONFIG)
            args = nct_config.build_argument_parser().parse_args([])
            options = nct_config.resolve_runtime_options(args, dict(nct_config.DEFAULT_CONFIG))
            session = nct.CaptureSession(options)
            session.enable_config_reload(args, path)
            config = dict(nct_config.DEFAULT_CONFIG)
            config["processes"] = []
            common.atomic_write_json(path, config)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertFalse(session._poll_config_reload(now=20.0))
                self.assertFalse(session._poll_config_reload(now=21.0))
            self.assertEqual(session.options["processes"], nct_config.DEFAULT_CONFIG["processes"])
            self.assertIn(
                '[Config] Reload rejected: config.json "processes" must contain at least one executable. Current runtime configuration unchanged.',
                output.getvalue(),
            )

    def test_live_reload_skips_obsolete_snapshot_if_config_changes_after_load(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            common.atomic_write_json(path, nct_config.DEFAULT_CONFIG)
            args = nct_config.build_argument_parser().parse_args([])
            options = nct_config.resolve_runtime_options(args, dict(nct_config.DEFAULT_CONFIG))
            session = nct.CaptureSession(options)
            session.enable_config_reload(args, path)

            first = dict(nct_config.DEFAULT_CONFIG)
            first["debug"] = True
            second = dict(nct_config.DEFAULT_CONFIG)
            second["debug"] = "global"
            common.atomic_write_json(path, first)

            original_snapshot = nct_config.load_exact_config_snapshot
            changed_during_snapshot = False

            def snapshot_then_save_newer(*snapshot_args, **snapshot_kwargs):
                nonlocal changed_during_snapshot
                if not changed_during_snapshot:
                    changed_during_snapshot = True
                    common.atomic_write_json(path, second)
                    raise nct_config.ConfigSnapshotChanged
                return original_snapshot(*snapshot_args, **snapshot_kwargs)

            with (
                mock.patch.object(nct_config, "load_exact_config_snapshot", side_effect=snapshot_then_save_newer),
                mock.patch.object(session, "_apply_reloaded_config", return_value=False) as apply_config,
            ):
                self.assertFalse(session._poll_config_reload(now=10.0))
                self.assertFalse(session._poll_config_reload(now=11.0))
                apply_config.assert_not_called()

                # The newer save gets its own normal debounce period and is then
                # applied exactly once instead of applying the obsolete snapshot.
                self.assertFalse(session._poll_config_reload(now=12.0))
                self.assertFalse(session._poll_config_reload(now=13.0))

            apply_config.assert_called_once()
            self.assertEqual(apply_config.call_args.args[0]["debug"], "global")

    def test_session_capture_config_metadata_sync_sends_normalized_worker_message(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG)
        session = nct.CaptureSession(options)
        session.manifest_path = Path("C:/output/session_session.json")
        stdin = io.StringIO()
        session.process = SimpleNamespace(stdin=stdin, poll=lambda: None)
        updated = dict(
            options,
            capture_mode="system-proxy",
            debug=True,
            proxy_port=8081,
            upstream_proxy="http://User:Secret@Proxy.EXAMPLE:3128",
            stop_on_exit=False,
            stop_on_exit_delay=20,
        )
        with mock.patch.object(session.config_metadata_updated, "wait", return_value=True):
            session._sync_session_capture_config_metadata(updated)
        message = common.parse_worker_message(stdin.getvalue().strip())
        assert message is not None
        self.assertEqual(message["type"], "config_metadata")
        self.assertEqual(message["capture_mode"], "system-proxy")
        self.assertEqual(message["processes"], nct_config.DEFAULT_CONFIG["processes"])
        self.assertEqual(message["debug"], "on")
        self.assertEqual(message["proxy_port"], 8081)
        self.assertEqual(message["upstream_proxy"], "http://proxy.example:3128")
        self.assertNotIn("Secret", stdin.getvalue())
        self.assertIs(message["stop_on_exit"], False)
        self.assertEqual(message["stop_on_exit_delay"], 20)
        self.assertEqual(message["token"], session.config_metadata_update_token)

    def test_worker_config_metadata_ack_unblocks_parent_sync(self) -> None:
        session = nct.CaptureSession(dict(nct_config.DEFAULT_CONFIG))
        session.config_metadata_update_token = "token123"
        payload = common.encode_worker_message("config_metadata_updated", token="token123")
        process = SimpleNamespace(stdout=io.StringIO(payload + "\n"), poll=lambda: 0)
        session._read_worker_output(process)
        self.assertTrue(session.config_metadata_updated.is_set())
        self.assertIsNone(session.config_metadata_update_error)

    def test_live_config_change_messages_are_consistent_and_safe(self) -> None:
        args = nct_config.build_argument_parser().parse_args([])
        options = nct_config.resolve_runtime_options(args, dict(nct_config.DEFAULT_CONFIG))
        session = nct.CaptureSession(options, cli_args=args)
        config = dict(nct_config.DEFAULT_CONFIG)
        config["upstream_proxy"] = "http://user:secret@proxy.example:3128"
        config["output_root"] = "output2"
        config["name_session_after_warframe_version"] = True
        output = io.StringIO()
        with (
            mock.patch.object(session, "_restart_capture_subsystem"),
            contextlib.redirect_stdout(output),
        ):
            self.assertFalse(session._apply_reloaded_config(config))
        text = output.getvalue()
        self.assertIn("[Config] Upstream proxy: Custom (http://proxy.example:3128)", text)
        self.assertNotIn("secret", text)
        self.assertIn("[Config] Output root:", text)
        self.assertIn("output2 (next launch)", text)
        self.assertIn("[Config] Version-based session naming: On (next session)", text)
        self.assertTrue(text.endswith("\n\n"))

    def test_live_auto_update_change_applies_on_next_launch(self) -> None:
        args = nct_config.build_argument_parser().parse_args([])
        options = nct_config.resolve_runtime_options(args, dict(nct_config.DEFAULT_CONFIG))
        session = nct.CaptureSession(options, cli_args=args)
        config = dict(nct_config.DEFAULT_CONFIG)
        config["auto_update"] = False
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertFalse(session._apply_reloaded_config(config))
        self.assertFalse(session.options["auto_update"])
        text = output.getvalue()
        self.assertIn("[Config] Change detected.", text)
        self.assertIn("Automatic updates: Off", text)
        self.assertIn("next launch", text)

    def test_live_invalid_auto_update_reports_error_and_keeps_current_setting(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            common.atomic_write_json(path, nct_config.DEFAULT_CONFIG)
            args = nct_config.build_argument_parser().parse_args([])
            options = nct_config.resolve_runtime_options(args, dict(nct_config.DEFAULT_CONFIG))
            session = nct.CaptureSession(options)
            session.enable_config_reload(args, path)
            invalid = dict(nct_config.DEFAULT_CONFIG)
            invalid["auto_update"] = "off"
            common.atomic_write_json(path, invalid)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertFalse(session._poll_config_reload(now=10.0))
                self.assertFalse(session._poll_config_reload(now=11.0))
        self.assertTrue(session.options["auto_update"])
        text = output.getvalue()
        self.assertIn("ERROR: config.json auto_update must be true or false.", text)
        self.assertIn("Reload rejected", text)

    def test_live_config_apply_failure_reports_rollback_separately(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            common.atomic_write_json(path, nct_config.DEFAULT_CONFIG)
            args = nct_config.build_argument_parser().parse_args([])
            options = nct_config.resolve_runtime_options(args, dict(nct_config.DEFAULT_CONFIG))
            session = nct.CaptureSession(options)
            session.enable_config_reload(args, path)
            config = dict(nct_config.DEFAULT_CONFIG)
            config["capture_mode"] = "system-proxy"
            common.atomic_write_json(path, config)
            output = io.StringIO()
            with (
                mock.patch.object(
                    session,
                    "_restart_capture_subsystem",
                    side_effect=nct_config.ConfigApplyError(
                        "Windows did not keep the required System Proxy settings (mismatch: ProxyEnable)",
                        rollback_restored=True,
                    ),
                ),
                mock.patch.object(session, "_sync_session_capture_config_metadata") as sync_metadata,
                contextlib.redirect_stdout(output),
            ):
                self.assertFalse(session._poll_config_reload(now=10.0))
                self.assertFalse(session._poll_config_reload(now=11.0))
            sync_metadata.assert_not_called()
        text = output.getvalue()
        self.assertIn(
            "[Config] Apply failed: Windows did not keep the required System Proxy settings (mismatch: ProxyEnable).",
            text,
        )
        self.assertIn("[Config] Previous runtime configuration restored.", text)
        self.assertNotIn("Reload rejected", text)
        self.assertTrue(text.endswith("\n\n"))

    def test_live_config_unrecoverable_rollback_marks_session_failed_and_stops(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            common.atomic_write_json(path, nct_config.DEFAULT_CONFIG)
            args = nct_config.build_argument_parser().parse_args([])
            options = nct_config.resolve_runtime_options(args, dict(nct_config.DEFAULT_CONFIG))
            session = nct.CaptureSession(options)
            session.enable_config_reload(args, path)
            changed = dict(nct_config.DEFAULT_CONFIG)
            changed["capture_mode"] = "system-proxy"
            common.atomic_write_json(path, changed)
            output = io.StringIO()
            with (
                mock.patch.object(
                    session,
                    "_restart_capture_subsystem",
                    side_effect=nct_config.ConfigApplyError(
                        "System Proxy activation failed and recovery remains unresolved",
                        rollback_restored=False,
                    ),
                ),
                contextlib.redirect_stdout(output),
            ):
                self.assertFalse(session._poll_config_reload(now=10.0))
                self.assertTrue(session._poll_config_reload(now=11.0))

            self.assertTrue(session.failed)
            self.assertTrue(session.shutdown_requested.is_set())
            self.assertEqual(session.end_reason, "config_reload_failure")
            self.assertIn("rollback could not be restored", session.failure_reason or "")
            self.assertIn("stopping Ninja Capture Tool", output.getvalue())

    def test_subsystem_restart_does_not_overwrite_unresolved_proxy_recovery(self) -> None:
        session = nct.CaptureSession(dict(nct_config.DEFAULT_CONFIG))
        new_options = dict(session.options)
        new_options["capture_mode"] = "system-proxy"
        with tempfile.TemporaryDirectory() as tmp:
            recovery = Path(tmp) / "proxy_recovery.json"
            recovery.write_text("{}", encoding="utf-8")
            with (
                mock.patch.object(session, "_stop_capture_subsystem_for_restart"),
                mock.patch.object(
                    session,
                    "_start_capture_subsystem_for_options",
                    side_effect=RuntimeError("activation failed"),
                ) as start_subsystem,
                mock.patch.object(common, "proxy_recovery_file", return_value=recovery),
            ):
                with self.assertRaises(nct_config.ConfigApplyError) as raised:
                    session._restart_capture_subsystem(new_options)
            self.assertFalse(raised.exception.rollback_restored)
            self.assertIn("unresolved System Proxy recovery data remains", str(raised.exception))
            self.assertEqual(start_subsystem.call_count, 1)
            self.assertEqual(recovery.read_text(encoding="utf-8"), "{}")

    def test_live_apply_failure_keeps_last_applied_config_signature(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            common.atomic_write_json(path, nct_config.DEFAULT_CONFIG)
            args = nct_config.build_argument_parser().parse_args([])
            options = nct_config.resolve_runtime_options(args, dict(nct_config.DEFAULT_CONFIG))
            session = nct.CaptureSession(options)
            initial_signature = nct_config.config_file_signature(path)
            session.enable_config_reload(args, path, initial_signature=initial_signature)

            changed = dict(nct_config.DEFAULT_CONFIG)
            changed["capture_mode"] = "system-proxy"
            common.atomic_write_json(path, changed)
            changed_signature = nct_config.config_file_signature(path)
            output = io.StringIO()
            with (
                mock.patch.object(
                    session,
                    "_restart_capture_subsystem",
                    side_effect=nct_config.ConfigApplyError(
                        "Windows did not keep the required System Proxy settings",
                        rollback_restored=True,
                    ),
                ) as restart_subsystem,
                contextlib.redirect_stdout(output),
            ):
                self.assertFalse(session._poll_config_reload(now=20.0))
                self.assertFalse(session._poll_config_reload(now=21.0))
                self.assertFalse(session._poll_config_reload(now=22.0))

            self.assertEqual(restart_subsystem.call_count, 1)
            self.assertEqual(session.options["capture_mode"], "local")
            self.assertEqual(session.config_signature, initial_signature)
            self.assertTrue(session.config_rejected_signature_set)
            self.assertEqual(session.config_rejected_signature, changed_signature)
            self.assertEqual(output.getvalue().count("[Config] Apply failed:"), 1)

    def test_successful_live_reload_advances_applied_config_signature(self) -> None:
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
            changed_signature = nct_config.config_file_signature(path)

            def apply_worker(new_options):
                session.options = dict(new_options)

            with (
                mock.patch.object(session, "_drain_worker_before_restart"),
                mock.patch.object(session, "_restart_worker_for_options", side_effect=apply_worker),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertFalse(session._poll_config_reload(now=30.0))
                self.assertFalse(session._poll_config_reload(now=31.0))

            self.assertEqual(session.options["debug"], True)
            self.assertEqual(session.config_signature, changed_signature)
            self.assertFalse(session.config_rejected_signature_set)
            self.assertIsNone(session.config_rejected_signature)

    def test_short_cli_aliases_match_long_options(self) -> None:
        parser = nct_config.build_argument_parser()
        args = parser.parse_args(
            [
                "-m",
                "system-proxy",
                "-p",
                "Launcher.exe",
                "--process",
                "Warframe.x64.exe",
                "-P",
                "9000",
                "-o",
                "captures/U43.5.4",
                "-d",
                "-u",
                "direct",
            ]
        )
        self.assertEqual(args.capture_mode, "system-proxy")
        self.assertEqual(args.process, ["Launcher.exe", "Warframe.x64.exe"])
        self.assertEqual(args.proxy_port, 9000)
        self.assertEqual(args.output, "captures/U43.5.4")
        self.assertTrue(args.debug)
        self.assertEqual(args.upstream_proxy, "direct")
        self.assertFalse(parser.parse_args(["-D"]).debug)
        self.assertEqual(parser.parse_args(["-d", "global"]).debug, "global")
        self.assertEqual(parser.parse_args(["--debug", "global"]).debug, "global")
        self.assertEqual(parser.parse_args(["--port", "9001"]).proxy_port, 9001)
        self.assertTrue(parser.parse_args(["-s"]).stop_on_exit)
        self.assertFalse(parser.parse_args(["-S"]).stop_on_exit)
        self.assertEqual(parser.parse_args(["-w", "30"]).stop_on_exit_delay, 30)
        self.assertTrue(parser.parse_args(["-r"]).remove_elevation_task)
        self.assertTrue(parser.parse_args(["-C"]).remove_https_certificate)

    def test_single_use_cli_options_reject_repeated_short_or_long_aliases(self) -> None:
        parser = nct_config.build_argument_parser()
        cases = (
            ["-m", "local", "--capture-mode", "system-proxy"],
            ["-P", "8080", "--port", "8081"],
            ["-o", "one", "--output", "two"],
            ["-u", "auto", "--upstream-proxy", "direct"],
            ["-d", "--debug"],
            ["-d", "--no-debug"],
            ["-d", "global", "--debug", "global"],
            ["-s", "--stop-on-exit"],
            ["-S", "--no-stop-on-exit"],
            ["-w", "15", "--stop-on-exit-delay", "30"],
            ["-r", "--remove-elevation-task"],
            ["-C", "--remove-https-certificate"],
        )
        for arguments in cases:
            with self.subTest(arguments=arguments), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    parser.parse_args(arguments)

    def test_command_line_options_override_config(self) -> None:
        config = dict(nct_config.DEFAULT_CONFIG)
        args = argparse.Namespace(
            capture_mode="system-proxy",
            process=None,
            stop_on_exit=None,
            stop_on_exit_delay=None,
            proxy_port=9000,
            debug=True,
            output=Path("from-cli/U43.5.4"),
            upstream_proxy="direct",
        )
        with mock.patch.object(common, "TOOL_DIR", Path("/tool")):
            options = nct_config.resolve_runtime_options(args, config)
        self.assertEqual(options["capture_mode"], "system-proxy")
        self.assertEqual(options["processes"], nct_config.DEFAULT_CONFIG["processes"])
        self.assertFalse(options["stop_on_exit"])
        self.assertEqual(options["stop_on_exit_delay"], 15)
        self.assertEqual(options["proxy_port"], 9000)
        self.assertTrue(options["debug"])
        self.assertEqual(options["output_root"], Path("/tool/output").resolve())
        self.assertEqual(options["output_path"], Path("/tool/from-cli/U43.5.4").resolve())
        self.assertEqual(options["upstream_proxy"], "direct")

    def test_version_session_naming_cli_and_config_precedence(self) -> None:
        parser = nct_config.build_argument_parser()
        configured = nct_config.resolve_runtime_options(
            parser.parse_args([]),
            dict(nct_config.DEFAULT_CONFIG, name_session_after_warframe_version=True),
        )
        self.assertTrue(configured["name_session_after_warframe_version"])

        cli_enabled = nct_config.resolve_runtime_options(
            parser.parse_args(["--version-session-name"]),
            dict(nct_config.DEFAULT_CONFIG, name_session_after_warframe_version=False),
        )
        self.assertTrue(cli_enabled["name_session_after_warframe_version"])

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with mock.patch.object(common, "TOOL_DIR", root):
                custom = nct_config.resolve_runtime_options(
                    parser.parse_args(["--output", "custom-session"]),
                    dict(nct_config.DEFAULT_CONFIG, name_session_after_warframe_version=True),
                )
            self.assertFalse(custom["name_session_after_warframe_version"])
            self.assertEqual(custom["output_path"], (root / "custom-session").resolve())

    def test_mode_incompatible_cli_overrides_are_rejected(self) -> None:
        parser = nct_config.build_argument_parser()
        cases = (
            (["-m", "local", "--port", "9000"], "--port"),
            (["-m", "local", "--upstream-proxy", "direct"], "--upstream-proxy"),
            (["-m", "system-proxy", "--process", "Launcher.exe"], "--process"),
            (["-m", "system-proxy", "--stop-on-exit"], "--stop-on-exit"),
            (["-m", "system-proxy", "--no-stop-on-exit"], "--no-stop-on-exit"),
            (["-m", "system-proxy", "--stop-on-exit-delay", "30"], "--stop-on-exit-delay"),
        )
        for arguments, option in cases:
            with self.subTest(arguments=arguments):
                args = parser.parse_args(arguments)
                with self.assertRaisesRegex(RuntimeError, re.escape(option)):
                    nct_config.resolve_runtime_options(args, nct_config.DEFAULT_CONFIG)

    def test_mode_specific_cli_overrides_are_dormant_when_config_selects_other_mode(self) -> None:
        parser = nct_config.build_argument_parser()

        system_proxy = dict(nct_config.DEFAULT_CONFIG, capture_mode="system-proxy", debug=False)
        process_override = nct_config.resolve_runtime_options(
            parser.parse_args(["--process", "Launcher.exe"]),
            system_proxy,
        )
        self.assertEqual(process_override["capture_mode"], "system-proxy")
        self.assertEqual(process_override["processes"], ["Launcher.exe"])

        stop_override = nct_config.resolve_runtime_options(
            parser.parse_args(["--stop-on-exit", "--stop-on-exit-delay", "30"]),
            system_proxy,
        )
        self.assertEqual(stop_override["capture_mode"], "system-proxy")
        self.assertFalse(stop_override["stop_on_exit"])
        self.assertEqual(stop_override["stop_on_exit_delay"], 30)

        local = dict(nct_config.DEFAULT_CONFIG, capture_mode="local")
        proxy_override = nct_config.resolve_runtime_options(
            parser.parse_args(["--port", "9000", "--upstream-proxy", "direct"]),
            local,
        )
        self.assertEqual(proxy_override["capture_mode"], "local")
        self.assertEqual(proxy_override["proxy_port"], 9000)
        self.assertEqual(proxy_override["upstream_proxy"], "direct")

        global_debug_args = parser.parse_args(["--debug", "global"])
        dormant_debug = nct_config.resolve_runtime_options(global_debug_args, system_proxy)
        self.assertEqual(dormant_debug["capture_mode"], "system-proxy")
        self.assertFalse(dormant_debug["debug"])
        active_debug = nct_config.resolve_runtime_options(global_debug_args, local)
        self.assertEqual(active_debug["debug"], "global")

    def test_mode_specific_config_values_are_allowed_when_not_overridden_on_cli(self) -> None:
        parser = nct_config.build_argument_parser()
        local = nct_config.resolve_runtime_options(
            parser.parse_args(["-m", "local"]),
            dict(nct_config.DEFAULT_CONFIG, proxy_port=9000, upstream_proxy="direct"),
        )
        self.assertEqual(local["proxy_port"], 9000)
        self.assertEqual(local["upstream_proxy"], "direct")
        system_proxy = nct_config.resolve_runtime_options(
            parser.parse_args(["-m", "system-proxy"]),
            dict(nct_config.DEFAULT_CONFIG, processes=["CustomLauncher.exe"]),
        )
        self.assertEqual(system_proxy["processes"], ["CustomLauncher.exe"])
        self.assertFalse(system_proxy["stop_on_exit"])

    def test_stop_on_exit_cli_overrides_config_and_validates_delay_conflicts(self) -> None:
        parser = nct_config.build_argument_parser()
        enabled = nct_config.resolve_runtime_options(
            parser.parse_args(["-s", "-w", "30"]),
            nct_config.DEFAULT_CONFIG,
        )
        self.assertTrue(enabled["stop_on_exit"])
        self.assertEqual(enabled["stop_on_exit_delay"], 30)

        configured = nct_config.resolve_runtime_options(
            parser.parse_args(["-w", "20"]),
            dict(nct_config.DEFAULT_CONFIG, stop_on_exit=True),
        )
        self.assertTrue(configured["stop_on_exit"])
        self.assertEqual(configured["stop_on_exit_delay"], 20)

        disabled = nct_config.resolve_runtime_options(
            parser.parse_args(["-S"]),
            dict(nct_config.DEFAULT_CONFIG, stop_on_exit=True, stop_on_exit_delay=25),
        )
        self.assertFalse(disabled["stop_on_exit"])
        self.assertEqual(disabled["stop_on_exit_delay"], 25)

        with self.assertRaisesRegex(RuntimeError, "requires --stop-on-exit"):
            nct_config.resolve_runtime_options(parser.parse_args(["-w", "20"]), nct_config.DEFAULT_CONFIG)
        with self.assertRaisesRegex(RuntimeError, "cannot be used with --no-stop-on-exit"):
            nct_config.resolve_runtime_options(parser.parse_args(["-S", "-w", "20"]), nct_config.DEFAULT_CONFIG)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args(["-s", "-S"])

    def test_runtime_paths_separate_portable_cache_from_machine_state(self) -> None:
        self.assertEqual(nct_config.CONFIG_FILE, common.TOOL_DIR / "config.json")
        self.assertEqual(common.DATA_DIR, common.TOOL_DIR / "data")
        with tempfile.TemporaryDirectory() as tmp:
            local_root = Path(tmp) / "DarkLotus" / "Ninja Capture Tool"
            with mock.patch.object(common, "nct_local_app_data_root", return_value=local_root):
                state = common.runtime_state_directory()
                self.assertEqual(state, local_root / "state" / common.installation_state_id(common.TOOL_DIR))
                self.assertEqual(common.mitmproxy_conf_directory(), local_root / "mitmproxy")
                self.assertEqual(common.proxy_recovery_file(), local_root / "state" / "proxy_recovery.json")
                self.assertEqual(common.session_recovery_file(), state / "session_recovery.json")
                self.assertEqual(common.warframe_version_state_file(), common.DATA_DIR / "warframe_version.json")
                self.assertEqual(common.update_state_file(), common.DATA_DIR / "update_state.json")
                self.assertEqual(common.update_temp_root(), common.TOOL_DIR / "temp")

    def test_mitmproxy_ca_directory_is_independent_of_installation_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            local_root = Path(tmp) / "DarkLotus" / "Ninja Capture Tool"
            with mock.patch.object(common, "nct_local_app_data_root", return_value=local_root):
                expected = local_root / "mitmproxy"
                self.assertEqual(common.mitmproxy_conf_directory(), expected)
                self.assertNotIn(common.installation_state_id(Path("D:/NCT-A")), str(expected))
                self.assertNotIn(common.installation_state_id(Path("E:/NCT-B")), str(expected))

    def test_proxy_recovery_file_is_independent_of_installation_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            local_root = Path(tmp) / "DarkLotus" / "Ninja Capture Tool"
            with mock.patch.object(common, "nct_local_app_data_root", return_value=local_root):
                expected = local_root / "state" / "proxy_recovery.json"
                self.assertEqual(common.proxy_recovery_file(), expected)
                self.assertNotIn(common.installation_state_id(Path("D:/NCT-A")), str(expected))
                self.assertNotIn(common.installation_state_id(Path("E:/NCT-B")), str(expected))

    def test_config_output_root_uses_windows_path_validation(self) -> None:
        for value in ("bad?root", "A:", "trailing.", "./captures", r"\Captures"):
            config = dict(nct_config.DEFAULT_CONFIG, output_root=value)
            with self.subTest(value=value), self.assertRaisesRegex(RuntimeError, "output_root"):
                nct_config.validate_config(config)

    def test_stop_on_exit_stops_after_configured_absence_delay(self) -> None:
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
            mock.patch.object(nct_runtime, "running_process_names", side_effect=[{"launcher.exe"}, set(), set()]),
            mock.patch.object(nct.time, "monotonic", side_effect=[100.0, 115.0]),
            mock.patch.object(nct.time, "sleep"),
            mock.patch.object(session, "log") as log,
        ):
            session.wait()
        log.assert_called_once_with("[Stopping] Selected processes remained absent for 15 seconds.")
        self.assertEqual(session.end_reason, "stop_on_exit")

    def test_config_restart_drain_waits_for_active_capture_and_uses_control_pipe(self) -> None:
        session = nct.CaptureSession(dict(nct_config.DEFAULT_CONFIG, output_root=Path("C:/output"), output_path=None))
        process = mock.Mock()
        process.poll.return_value = None
        process.stdin = mock.Mock()
        session.process = process
        session.worker_activity_seen = True
        session.worker_active_captures = 1
        session.worker_drained = mock.Mock()
        session.worker_drained.wait.side_effect = [False, True]
        output = io.StringIO()
        with (
            mock.patch.object(session, "_poll_restart_hotkey") as poll_restart_hotkey,
            contextlib.redirect_stdout(output),
        ):
            session._drain_worker_before_restart()
        process.stdin.write.assert_called_once_with(common.encode_worker_message("drain") + "\n")
        process.stdin.flush.assert_called_once_with()
        poll_restart_hotkey.assert_called_once_with(defer_restart=True)
        self.assertIn("Waiting for active capture to finish before restarting...", output.getvalue())

    def test_config_restart_drain_allows_more_than_three_hours_with_continuous_progress(self) -> None:
        session = nct.CaptureSession(dict(nct_config.DEFAULT_CONFIG, output_root=Path("C:/output"), output_path=None))
        process = mock.Mock()
        process.poll.return_value = None
        process.stdin = mock.Mock()
        session.process = process
        session.worker_activity_seen = True
        session.worker_active_captures = 1
        session.worker_drained = mock.Mock()
        clock = [0.0]
        waits = iter((3600.0, 7200.0, 10801.0, None))

        def wait(_timeout: float) -> bool:
            value = next(waits)
            if value is None:
                return True
            clock[0] = value
            with session.worker_activity_lock:
                session.worker_last_progress = value
            return False

        session.worker_drained.wait.side_effect = wait
        output = io.StringIO()
        with mock.patch.object(nct.time, "monotonic", side_effect=lambda: clock[0]), contextlib.redirect_stdout(output):
            session._drain_worker_before_restart()

        self.assertNotIn("made no progress for 3 hours", output.getvalue())
        self.assertEqual(session.worker_drained.wait.call_count, 4)

    def test_config_restart_drain_stops_after_three_hours_without_progress(self) -> None:
        session = nct.CaptureSession(dict(nct_config.DEFAULT_CONFIG, output_root=Path("C:/output"), output_path=None))
        process = mock.Mock()
        process.poll.return_value = None
        process.stdin = mock.Mock()
        session.process = process
        session.worker_activity_seen = True
        session.worker_active_captures = 1
        session.worker_drained = mock.Mock()
        clock = [0.0]

        def wait(_timeout: float) -> bool:
            clock[0] = float(3 * 60 * 60)
            return False

        session.worker_drained.wait.side_effect = wait
        output = io.StringIO()
        with mock.patch.object(nct.time, "monotonic", side_effect=lambda: clock[0]), contextlib.redirect_stdout(output):
            session._drain_worker_before_restart()

        self.assertIn("WARNING: Active capture made no progress for 3 hours; restarting the capture worker anyway.", output.getvalue())
        self.assertEqual(session.worker_drained.wait.call_count, 1)

    def test_local_worker_command_targets_only_configured_processes(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG)
        options["capture_mode"] = "local"
        with mock.patch.object(nct.sys, "frozen", False, create=True):
            command = nct_runtime.worker_command(Path("C:/session"), options, manifest_path=Path("C:/session_session.json"))
        mode = command[command.index("--mode") + 1]
        self.assertEqual(mode, "local:Launcher.exe,Warframe.x64.exe")
        self.assertEqual(command[command.index("--listen-port") + 1], "0")

    def test_capture_store_updates_capture_configuration_metadata_and_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp) / "session"
            session.mkdir()
            manifest_path = self.manifest_path_for(session)
            options = dict(nct_config.DEFAULT_CONFIG, output_root=Path(tmp), output_path=None)
            capture.initialize_session_manifest(session, options, manifest_path)
            store = capture.CaptureStore(session, manifest_path=manifest_path)
            with mock.patch.object(capture, "current_timestamp", return_value="2026-09-12T09:15:00+02:00"):
                store.update_capture_config_metadata(
                    "system-proxy",
                    ["Launcher.exe", "Warframe.x64.exe"],
                    "on",
                    8081,
                    "http://user:secret@proxy.example:3128",
                    False,
                    20,
                )
            data = common.read_json_object(manifest_path)
            self.assertEqual(data["capture_mode"], "system-proxy")
            self.assertEqual(data["processes"], ["Launcher.exe", "Warframe.x64.exe"])
            self.assertEqual(data["debug"], "on")
            self.assertEqual(data["proxy_port"], 8081)
            self.assertEqual(data["upstream_proxy"], "http://proxy.example:3128")
            self.assertIs(data["stop_on_exit"], False)
            self.assertEqual(data["stop_on_exit_delay"], 20)
            self.assertNotIn("secret", json.dumps(data))
            self.assertEqual(len(data["capture_config_history"]), 2)
            self.assertEqual(
                data["capture_config_history"][-1],
                {
                    "changed_at": "2026-09-12T09:15:00+02:00",
                    "capture_mode": "system-proxy",
                    "processes": ["Launcher.exe", "Warframe.x64.exe"],
                    "debug": "on",
                    "proxy_port": 8081,
                    "upstream_proxy": "http://proxy.example:3128",
                    "stop_on_exit": False,
                    "stop_on_exit_delay": 20,
                },
            )

            # Re-applying the same effective state refreshes the current fields but
            # must not create duplicate history entries.
            store.update_capture_config_metadata(
                "system-proxy",
                ["Launcher.exe", "Warframe.x64.exe"],
                "on",
                8081,
                "http://proxy.example:3128",
                False,
                20,
            )
            data = common.read_json_object(manifest_path)
            self.assertEqual(len(data["capture_config_history"]), 2)

    def test_update_cli_options_are_mutually_exclusive_and_single_use(self) -> None:
        parser = nct_config.build_argument_parser()
        cases = (
            ["-a", "--auto-update"],
            ["-n", "--no-auto-update"],
            ["-U", "--check-update"],
            ["-a", "-n"],
            ["-a", "-U"],
            ["-n", "-U"],
        )
        for arguments in cases:
            with self.subTest(arguments=arguments), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    parser.parse_args(arguments)

    def test_configured_auto_update_skips_github_during_check_cooldown(self) -> None:
        args = SimpleNamespace(no_auto_update=False, auto_update=False)
        with (
            mock.patch.object(update.sys, "frozen", True, create=True),
            mock.patch.object(update, "automatic_update_check_due", return_value=False),
            mock.patch.object(update, "check_for_update") as check,
        ):
            self.assertIsNone(update.handle_automatic_update(args, [], True))
        check.assert_not_called()

    def test_updater_preserves_user_config_update_preferences_and_unowned_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install = root / "install"
            stage = root / "work" / "stage"
            install.mkdir(parents=True)
            stage.mkdir(parents=True)
            (install / "data").mkdir(parents=True)
            (stage / "data" / "licenses").mkdir(parents=True)

            user_config = dict(nct_config.DEFAULT_CONFIG, debug=True, proxy_port=9000, auto_update=False)
            (install / "config.json").write_text(json.dumps(user_config), encoding="utf-8")
            (install / "data" / "custom-user-data.txt").write_text("keep-me", encoding="utf-8")
            (install / "data" / "warframe_version.json").write_text('{"high_water_version": "43.5.4"}', encoding="utf-8")
            (install / "data" / "update_state.json").write_text('{"last_successful_check": 123}', encoding="utf-8")
            (install / "NinjaCaptureTool.exe").write_bytes(b"old-main")

            (stage / "config.json").write_text(json.dumps(nct_config.DEFAULT_CONFIG), encoding="utf-8")
            (stage / "data" / "licenses" / "new.txt").write_text("new", encoding="utf-8")
            (stage / "NinjaCaptureTool.exe").write_bytes(b"new-main")
            (stage / "README.txt").write_text("new readme", encoding="utf-8")
            self._write_stage_release_manifest(stage)

            backup, _ = update.install_staged_release(stage, install, common.VERSION)
            self.assertEqual(json.loads((install / "config.json").read_text(encoding="utf-8")), user_config)
            self.assertFalse(json.loads((install / "config.json").read_text(encoding="utf-8"))["auto_update"])
            self.assertEqual((install / "data" / "custom-user-data.txt").read_text(encoding="utf-8"), "keep-me")
            self.assertEqual(common.read_json_object(install / "data" / "warframe_version.json"), {"high_water_version": "43.5.4"})
            self.assertEqual(common.read_json_object(install / "data" / "update_state.json"), {"last_successful_check": 123})
            self.assertEqual((install / "data" / "licenses" / "new.txt").read_text(encoding="utf-8"), "new")
            self.assertEqual((install / "NinjaCaptureTool.exe").read_bytes(), b"new-main")
            self.assertEqual((install / "README.txt").read_text(encoding="utf-8"), "new readme")
            self.assertTrue(backup.is_dir())
