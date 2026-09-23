# Run from the project root with: py -B -m unittest discover -s tests
from support import *

class WindowsProxyTests(NctTestBase):
    def test_config_custom_proxy_and_process_casing_are_not_normalized(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            proxy = "HTTP://User:PaSSword@ProxyHost:8080"
            config = dict(nct_config.DEFAULT_CONFIG)
            config.update({
                "processes": ["Launcher.exe", "launcher.exe"],
                "upstream_proxy": proxy,
            })
            path.write_text(json.dumps(config), encoding="utf-8")
            loaded = nct_config.load_config(path)
            self.assertEqual(loaded["processes"], ["Launcher.exe", "launcher.exe"])
            self.assertEqual(loaded["upstream_proxy"], proxy)

    def test_proxy_worker_stages_external_runtime_only_for_local_capture(self) -> None:
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
            manifest = Path(tmp) / "session_session.json"
            modules = {
                "mitmproxy": mitmproxy,
                "mitmproxy.tools": mock.MagicMock(),
                "mitmproxy.tools.dump": dump,
            }
            with (
                mock.patch.dict(nct.sys.modules, modules),
                mock.patch.object(capture, "CaptureAddon", return_value=object()),
                mock.patch.object(nct, "patch_mitmproxy_1223_quic_host_filter", return_value=True),
                mock.patch.object(nct, "patch_mitmproxy_1223_local_process_metadata", return_value=True),
                mock.patch.object(nct, "prepare_windows_local_capture_runtime") as prepare_runtime,
            ):
                nct.asyncio.run(nct.run_proxy_worker(session, "local:Launcher.exe", 0, "off", manifest_path=manifest))
                prepare_runtime.assert_called_once_with()
                prepare_runtime.reset_mock()
                nct.asyncio.run(nct.run_proxy_worker(session, "regular", 8080, "off", manifest_path=manifest))
                prepare_runtime.assert_not_called()

    def test_live_local_global_to_system_proxy_normal_debug_is_one_valid_change(self) -> None:
        args = nct_config.build_argument_parser().parse_args([])
        initial = dict(nct_config.DEFAULT_CONFIG)
        initial["debug"] = "global"
        options = nct_config.resolve_runtime_options(args, initial)
        session = nct.CaptureSession(options, cli_args=args)
        config = dict(nct_config.DEFAULT_CONFIG)
        config["capture_mode"] = "system-proxy"
        config["debug"] = True
        output = io.StringIO()
        with (
            mock.patch.object(session, "_restart_capture_subsystem") as restart_subsystem,
            mock.patch.object(nct_runtime, "set_console_title") as set_title,
            contextlib.redirect_stdout(output),
        ):
            self.assertFalse(session._apply_reloaded_config(config))
        restart_subsystem.assert_called_once()
        set_title.assert_called_once_with("system-proxy")
        text = output.getvalue()
        self.assertIn("[Config] Capture mode: Local -> System Proxy", text)
        self.assertIn("[Config] Debug: Global -> On", text)
        self.assertNotIn("Global debug requires Local Capture", text)

    def test_capture_subsystem_restart_does_not_tear_down_worker_when_proxy_restore_is_unsafe(self) -> None:
        session = nct.CaptureSession(dict(nct_config.DEFAULT_CONFIG, output_root=Path("C:/output"), output_path=None))
        new_options = dict(session.options, capture_mode="system-proxy")
        with (
            mock.patch.object(
                session,
                "_stop_capture_subsystem_for_restart",
                side_effect=RuntimeError("proxy ownership changed"),
            ),
            mock.patch.object(session, "_stop_worker") as stop_worker,
        ):
            with self.assertRaisesRegex(RuntimeError, "proxy ownership changed"):
                session._restart_capture_subsystem(new_options)
        stop_worker.assert_not_called()

    def test_manual_h_cache_fetch_uses_resolved_external_upstream_proxy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp) / "session"
            session.mkdir()
            manifest_path = self.manifest_path_for(session)
            capture.initialize_session_manifest(session, nct_config.DEFAULT_CONFIG, manifest_path)
            store = capture.CaptureStore(
                session,
                manifest_path,
                manual_fetch_upstream="http://proxy.test:3128",
                manual_fetch_upstream_auth="user:password",
            )
            proxy_handler = object()
            auth_handler = object()
            password_manager = mock.Mock()
            opener = object()
            with (
                mock.patch.object(capture.urllib_request, "ProxyHandler", return_value=proxy_handler) as proxy,
                mock.patch.object(
                    capture.urllib_request,
                    "HTTPPasswordMgrWithDefaultRealm",
                    return_value=password_manager,
                ),
                mock.patch.object(
                    capture.urllib_request,
                    "ProxyBasicAuthHandler",
                    return_value=auth_handler,
                ) as auth,
                mock.patch.object(capture.urllib_request, "build_opener", return_value=opener) as build,
            ):
                self.assertIs(store._manual_fetch_opener(), opener)
            proxy.assert_called_once_with(
                {
                    "http": "http://proxy.test:3128",
                    "https": "http://proxy.test:3128",
                }
            )
            password_manager.add_password.assert_called_once_with(
                None,
                "http://proxy.test:3128",
                "user",
                "password",
            )
            auth.assert_called_once_with(password_manager)
            self.assertEqual(build.call_count, 1)
            args = build.call_args.args
            self.assertEqual(args[:2], (proxy_handler, auth_handler))
            self.assertIsInstance(args[2], capture.ManualFetchRedirectHandler)

    def test_mitmproxy_1223_quic_host_filter_patch_uses_safe_protocol_detection(self) -> None:
        class FakeNeedsMoreData(Exception):
            pass

        class FakeNextLayer:
            @staticmethod
            def _get_client_hello(context, data_client):
                return "tcp-original"

        next_layer = ModuleType("mitmproxy.addons.next_layer")
        next_layer.NextLayer = FakeNextLayer
        next_layer.NeedsMoreData = FakeNeedsMoreData
        next_layer._starts_like_quic = lambda data, address: data.startswith(b"QUIC")
        next_layer.starts_like_dtls_record = lambda data: data.startswith(b"DTLS")
        next_layer.quic_parse_client_hello_from_datagrams = lambda datagrams: None
        next_layer.dtls_parse_client_hello = lambda data: None
        addons = ModuleType("mitmproxy.addons")
        addons.next_layer = next_layer
        mitmproxy = ModuleType("mitmproxy")
        mitmproxy.__path__ = []
        mitmproxy.addons = addons
        tcp_context = SimpleNamespace(client=SimpleNamespace(transport_protocol="tcp"), server=SimpleNamespace(address=("1.2.3.4", 443)))
        udp_context = SimpleNamespace(client=SimpleNamespace(transport_protocol="udp"), server=SimpleNamespace(address=("1.2.3.4", 443)))
        modules = {"mitmproxy": mitmproxy, "mitmproxy.addons": addons, "mitmproxy.addons.next_layer": next_layer}
        with mock.patch.dict(nct.sys.modules, modules):
            self.assertTrue(nct.patch_mitmproxy_1223_quic_host_filter())
            patched = FakeNextLayer._get_client_hello
            self.assertEqual(patched(tcp_context, b"anything"), "tcp-original")
            self.assertIsNone(patched(udp_context, b"short"))
            with self.assertRaises(FakeNeedsMoreData):
                patched(udp_context, b"QUIC incomplete")

    def test_mitmproxy_1223_local_process_metadata_patch_copies_redirector_metadata(self) -> None:
        class FakeLiveConnectionHandler:
            def __init__(self, reader, writer, options, mode):
                self.client = SimpleNamespace()

        server = ModuleType("mitmproxy.proxy.server")
        server.LiveConnectionHandler = FakeLiveConnectionHandler
        proxy = ModuleType("mitmproxy.proxy")
        proxy.__path__ = []
        proxy.server = server
        mitmproxy = ModuleType("mitmproxy")
        mitmproxy.__path__ = []
        mitmproxy.proxy = proxy
        modules = {
            "mitmproxy": mitmproxy,
            "mitmproxy.proxy": proxy,
            "mitmproxy.proxy.server": server,
        }
        values = {"pid": 24680, "process_name": r"C:\Games\Warframe\Warframe.x64.exe"}
        writer = SimpleNamespace(get_extra_info=lambda name: values.get(name))
        with mock.patch.dict(nct.sys.modules, modules):
            self.assertTrue(nct.patch_mitmproxy_1223_local_process_metadata())
            handler = FakeLiveConnectionHandler(None, writer, None, None)

        self.assertEqual(handler.client._nct_process_pid, 24680)
        self.assertEqual(
            handler.client._nct_process_name,
            r"C:\Games\Warframe\Warframe.x64.exe",
        )

    def test_worker_consumes_upstream_credentials_from_environment(self) -> None:
        captured: dict[str, object] = {}
        class FakeOptions:
            def __init__(self, **kwargs):
                captured.update(kwargs)
        class FakeAddons:
            def add(self, addon):
                pass
        class FakeMaster:
            def __init__(self, options, with_termlog=False, with_dumper=False):
                self.addons = FakeAddons()
                self.stopped = nct.asyncio.Event()
            async def run(self):
                await nct.asyncio.wait_for(self.stopped.wait(), 1.0)
            def shutdown(self):
                captured["shutdown"] = True
                self.stopped.set()
        mitmproxy = mock.MagicMock()
        mitmproxy.options.Options = FakeOptions
        dump = mock.MagicMock()
        dump.DumpMaster = FakeMaster
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(
            nct.sys.modules, {"mitmproxy": mitmproxy, "mitmproxy.tools": mock.MagicMock(), "mitmproxy.tools.dump": dump}
        ), mock.patch.object(
            common, "mitmproxy_conf_directory", return_value=Path(tmp) / "conf"
        ), mock.patch.object(
            capture, "CaptureAddon", return_value=object()
        ) as capture_addon, mock.patch.dict(
            nct.os.environ, {nct.UPSTREAM_AUTH_ENV: "user:password"}, clear=False
        ), mock.patch.object(
            nct.sys, "stdin", io.StringIO("")
        ):
            session = Path(tmp) / "session"
            manifest_path = Path(tmp) / "session_session.json"
            nct.asyncio.run(nct.run_proxy_worker(session, "upstream:http://proxy.test:3128", 8080, "off", manifest_path=manifest_path))
            self.assertNotIn(nct.UPSTREAM_AUTH_ENV, nct.os.environ)
        self.assertEqual(captured["upstream_auth"], "user:password")
        capture_addon.assert_called_once_with(
            session,
            manifest_path=manifest_path,
            debug=False,
            drain_requested=mock.ANY,
            worker_protocol_enabled=True,
            manual_fetch_upstream="http://proxy.test:3128",
            manual_fetch_upstream_auth="user:password",
        )
        self.assertTrue(captured["shutdown"])

    def test_worker_joins_precreated_job_before_starting_proxy_runtime(self) -> None:
        events: list[str] = []
        def fail_run(coroutine):
            events.append("run")
            coroutine.close()
            return None
        with (
            mock.patch.object(nct_runtime, "join_worker_job_from_environment", side_effect=lambda: events.append("job")),
            mock.patch.object(nct, "install_worker_stop_handler", side_effect=lambda: events.append("signal")),
            mock.patch.object(nct.asyncio, "run", side_effect=fail_run),
        ):
            self.assertEqual(
                nct.worker_main(
                    ["--proxy-worker", "--session", ".", "--manifest", "session.json", "--mode", "local", "--listen-port", "0", "--debug-worker", "off"]
                ),
                0,
            )
        self.assertEqual(events, ["job", "signal", "run"])

    def test_system_proxy_worker_command_uses_upstream_mode(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG)
        options["capture_mode"] = "system-proxy"
        with mock.patch.object(nct.sys, "frozen", False, create=True):
            command = nct_runtime.worker_command(Path("C:/session"), options, "http://proxy.test:3128", manifest_path=Path("C:/session_session.json"))
        self.assertEqual(command[command.index("--mode") + 1], "upstream:http://proxy.test:3128")
        self.assertEqual(command[command.index("--listen-port") + 1], "8080")

    def test_basic_upstream_auth_is_passed_to_worker_without_putting_it_in_command(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG)
        options["capture_mode"] = "system-proxy"
        session = nct.CaptureSession(dict(options, output_root=Path("C:/output"), output_path=None))
        session.session_root = Path("C:/session")
        session.manifest_path = Path("C:/session_session.json")
        fake_process = SimpleNamespace(stdout=io.StringIO(""))
        with (
            mock.patch.object(nct.subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200, create=True),
            mock.patch.object(nct.subprocess, "CREATE_NO_WINDOW", 0x08000000, create=True),
            mock.patch.object(nct.subprocess, "Popen", return_value=fake_process) as popen,
            mock.patch.object(nct_runtime, "create_worker_job", return_value=("job", "worker-job")) as create_job,
            mock.patch.object(nct.threading, "Thread") as thread,
        ):
            session._start_worker("http://proxy.test:3128", "user:password")
        command = popen.call_args.args[0]
        environment = popen.call_args.kwargs["env"]
        self.assertNotIn("user:password", command)
        self.assertEqual(environment[nct.UPSTREAM_AUTH_ENV], "user:password")
        self.assertEqual(environment[nct_runtime.WORKER_JOB_ENV], "worker-job")
        self.assertEqual(popen.call_args.kwargs["creationflags"], 0x00000200 | 0x08000000)
        create_job.assert_called_once_with()
        self.assertEqual(session.worker_job, "job")
        thread.return_value.start.assert_called_once_with()

    def test_simple_existing_proxy_is_chained_automatically(self) -> None:
        settings = self.proxy_settings(
            ProxyEnable={"value": 1, "type": 4},
            ProxyServer={"value": "proxy.test:3128", "type": 1},
            AutoDetect={"value": 0, "type": 4},
        )
        self.assertEqual(windows_proxy.resolve_upstream_proxy("auto", settings), ("http://proxy.test:3128", None))

    def test_protocol_specific_windows_proxy_uses_https_entry(self) -> None:
        settings = self.proxy_settings(
            ProxyEnable={"value": 1, "type": 4},
            ProxyServer={"value": "http=plain.test:8080;https=secure.test:8443", "type": 1},
            AutoDetect={"value": 0, "type": 4},
        )
        self.assertEqual(windows_proxy.resolve_upstream_proxy("auto", settings), ("http://secure.test:8443", None))

    def test_socks_only_windows_proxy_is_not_silently_bypassed(self) -> None:
        settings = self.proxy_settings(
            ProxyEnable={"value": 1, "type": 4},
            ProxyServer={"value": "socks=socks.test:1080", "type": 1},
            AutoDetect={"value": 0, "type": 4},
        )
        with self.assertRaisesRegex(RuntimeError, "SOCKS"):
            windows_proxy.resolve_upstream_proxy("auto", settings)

    def test_target_bypass_means_direct_upstream(self) -> None:
        settings = self.proxy_settings(
            ProxyEnable={"value": 1, "type": 4},
            ProxyServer={"value": "proxy.test:3128", "type": 1},
            ProxyOverride={"value": "*.warframe.com;<local>", "type": 1},
            AutoDetect={"value": 0, "type": 4},
        )
        self.assertTrue(windows_proxy.target_bypasses_existing_proxy(settings))
        self.assertEqual(windows_proxy.resolve_upstream_proxy("auto", settings), (None, None))

    def test_preserved_proxy_override_removes_target_bypass_only(self) -> None:
        settings = self.proxy_settings(
            ProxyOverride={"value": "*.warframe.com;*.company.local;<local>;example.com", "type": 1}
        )
        value = windows_proxy.preserved_proxy_override(settings)
        self.assertNotIn("*.warframe.com", value)
        self.assertIn("*.company.local", value)
        self.assertIn("example.com", value)
        self.assertIn("<local>", value)

    def test_pac_and_wpad_use_windows_auto_proxy_resolution(self) -> None:
        pac = self.proxy_settings(AutoConfigURL={"value": "https://proxy.test/proxy.pac", "type": 1})
        with mock.patch.object(
            windows_proxy,
            "winhttp_auto_proxy_for_url",
            return_value=("http://pac-proxy.test:8080", None),
        ) as resolve:
            self.assertEqual(
                windows_proxy.resolve_upstream_proxy("auto", pac),
                ("http://pac-proxy.test:8080", None),
            )
        resolve.assert_called_once_with(windows_proxy.TARGET_URL, pac_url="https://proxy.test/proxy.pac")

        wpad = self.proxy_settings(AutoDetect={"value": 1, "type": 4})
        with mock.patch.object(windows_proxy, "winhttp_auto_proxy_for_url", return_value=None) as resolve:
            self.assertEqual(windows_proxy.resolve_upstream_proxy("auto", wpad), (None, None))
        resolve.assert_called_once_with(windows_proxy.TARGET_URL, autodetect=True)

    def test_wpad_failure_without_manual_fallback_is_reported(self) -> None:
        settings = self.proxy_settings(AutoDetect={"value": 1, "type": 4})
        with mock.patch.object(windows_proxy, "winhttp_auto_proxy_for_url", side_effect=OSError("WPAD unavailable")):
            with self.assertRaisesRegex(RuntimeError, "no manual fallback proxy"):
                windows_proxy.resolve_upstream_proxy("auto", settings)

    def test_manual_proxy_is_fallback_when_pac_resolution_fails(self) -> None:
        settings = self.proxy_settings(
            ProxyEnable={"value": 1, "type": 4},
            ProxyServer={"value": "fallback.test:3128", "type": 1},
            AutoConfigURL={"value": "https://proxy.test/proxy.pac", "type": 1},
        )
        with mock.patch.object(windows_proxy, "winhttp_auto_proxy_for_url", side_effect=OSError("PAC unavailable")):
            self.assertEqual(
                windows_proxy.resolve_upstream_proxy("auto", settings),
                ("http://fallback.test:3128", None),
            )

    def test_explicit_basic_authenticated_upstream_proxy_is_supported(self) -> None:
        self.assertEqual(
            windows_proxy.parse_upstream_proxy("http://user:p%40ss@proxy.test:8080"),
            ("http://proxy.test:8080", "user:p@ss"),
        )

    def test_upstream_proxy_loop_detection_recognizes_localhost_spellings(self) -> None:
        for upstream in (
            "http://127.0.0.1:8080",
            "https://localhost:8080",
            "http://localhost.:8080",
        ):
            with self.subTest(upstream=upstream):
                self.assertTrue(windows_proxy.upstream_points_to_local_proxy(upstream, 8080))
        self.assertFalse(windows_proxy.upstream_points_to_local_proxy("http://localhost:8081", 8080))
        self.assertFalse(windows_proxy.upstream_points_to_local_proxy("http://proxy.test:8080", 8080))

    def test_proxy_change_notification_checks_both_wininet_calls(self) -> None:
        internet_set_option = mock.Mock(side_effect=[True, True])
        wininet = SimpleNamespace(InternetSetOptionW=internet_set_option)
        with (
            mock.patch.object(windows_proxy.ctypes, "WinDLL", return_value=wininet, create=True),
            mock.patch.object(windows_proxy.ctypes, "set_last_error", create=True) as set_last_error,
        ):
            windows_proxy.notify_windows_proxy_changed()
        self.assertEqual([call.args[1] for call in internet_set_option.call_args_list], [39, 37])
        self.assertEqual(set_last_error.call_count, 2)

    def test_proxy_change_notification_failure_is_reported(self) -> None:
        internet_set_option = mock.Mock(return_value=False)
        wininet = SimpleNamespace(InternetSetOptionW=internet_set_option)
        with (
            mock.patch.object(windows_proxy.ctypes, "WinDLL", return_value=wininet, create=True),
            mock.patch.object(windows_proxy.ctypes, "set_last_error", create=True),
            mock.patch.object(windows_proxy.ctypes, "get_last_error", return_value=5, create=True),
        ):
            with self.assertRaisesRegex(RuntimeError, "Could not notify Windows"):
                windows_proxy.notify_windows_proxy_changed()

    def test_proxy_verification_accepts_windows_normalized_disabled_values(self) -> None:
        before = self.proxy_settings(ProxyEnable={"value": 0, "type": 4})
        expected = windows_proxy.build_local_proxy_settings(before, 8080)
        current = dict(expected)
        current["AutoDetect"] = None
        current["AutoConfigURL"] = {"value": "", "type": 1}
        current["ProxyOverride"] = {"value": "<LOCAL>", "type": 1}
        self.assertEqual(windows_proxy.proxy_settings_mismatches(current, expected), [])
        self.assertTrue(windows_proxy.proxy_settings_equivalent(current, expected))

    def test_proxy_verification_retries_transient_windows_readback(self) -> None:
        before = self.proxy_settings(ProxyEnable={"value": 0, "type": 4})
        expected = windows_proxy.build_local_proxy_settings(before, 8080)
        transient = dict(expected)
        transient["ProxyEnable"] = {"value": 0, "type": 4}
        with (
            mock.patch.object(windows_proxy, "get_proxy_settings", side_effect=[transient, expected]) as readback,
            mock.patch.object(windows_proxy.time, "sleep") as sleep,
        ):
            self.assertEqual(windows_proxy.verify_applied_proxy_settings(expected), expected)
        self.assertEqual(readback.call_count, 2)
        sleep.assert_called_once_with(windows_proxy._PROXY_VERIFY_RETRY_DELAY_SECONDS)

    def test_proxy_verification_reports_only_mismatched_field_names(self) -> None:
        before = self.proxy_settings(ProxyEnable={"value": 0, "type": 4})
        expected = windows_proxy.build_local_proxy_settings(before, 8080)
        current = dict(expected)
        current["ProxyServer"] = {"value": "other.proxy:3128", "type": 1}
        with (
            mock.patch.object(windows_proxy, "get_proxy_settings", return_value=current),
            mock.patch.object(windows_proxy.time, "sleep"),
        ):
            with self.assertRaisesRegex(RuntimeError, r"mismatch: ProxyServer") as raised:
                windows_proxy.verify_applied_proxy_settings(expected)
        self.assertNotIn("other.proxy", str(raised.exception))

    def test_activate_proxy_returns_windows_normalized_settings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "proxy_recovery.json"
            before = self.proxy_settings(ProxyEnable={"value": 0, "type": 4})
            expected = windows_proxy.build_local_proxy_settings(before, 8080)
            current = dict(expected)
            current["AutoDetect"] = None
            with (
                mock.patch.object(windows_proxy, "apply_proxy_settings") as apply,
                mock.patch.object(windows_proxy, "verify_applied_proxy_settings", return_value=current),
            ):
                self.assertEqual(windows_proxy.activate_local_proxy(before, Path(tmp), 8080, path), current)
            apply.assert_called_once_with(expected)
            self.assertTrue(path.exists())

    def test_proxy_recovery_accepts_windows_normalized_applied_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "proxy_recovery.json"
            before = self.proxy_settings(ProxyEnable={"value": 0, "type": 4})
            applied = windows_proxy.build_local_proxy_settings(before, 8080)
            current = dict(applied)
            current["AutoDetect"] = None
            current["AutoConfigURL"] = {"value": "", "type": 1}
            common.atomic_write_json(path, windows_proxy.make_recovery_state(before, applied, Path(tmp), 8080))
            with (
                mock.patch.object(windows_proxy, "get_proxy_settings", side_effect=[current, before]),
                mock.patch.object(windows_proxy, "apply_proxy_settings") as restore,
            ):
                self.assertEqual(windows_proxy.restore_stale_recovery(path), "restored")
            restore.assert_called_once_with(before)
            self.assertFalse(path.exists())

    def test_proxy_recovery_restores_only_when_nct_still_owns_settings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "proxy_recovery.json"
            before = self.proxy_settings(ProxyEnable={"value": 0, "type": 4})
            applied = windows_proxy.build_local_proxy_settings(before, 8080)
            common.atomic_write_json(path, windows_proxy.make_recovery_state(before, applied, Path(tmp), 8080))
            with (
                mock.patch.object(windows_proxy, "get_proxy_settings", side_effect=[applied, before]),
                mock.patch.object(windows_proxy, "apply_proxy_settings") as restore,
            ):
                self.assertEqual(windows_proxy.restore_stale_recovery(path), "restored")
            restore.assert_called_once_with(before)
            self.assertFalse(path.exists())

    def test_proxy_recovery_discards_record_when_settings_are_already_restored(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "proxy_recovery.json"
            before = self.proxy_settings(ProxyEnable={"value": 0, "type": 4})
            applied = windows_proxy.build_local_proxy_settings(before, 8080)
            common.atomic_write_json(path, windows_proxy.make_recovery_state(before, applied, Path(tmp), 8080))
            with (
                mock.patch.object(windows_proxy, "get_proxy_settings", return_value=before),
                mock.patch.object(windows_proxy, "apply_proxy_settings") as restore,
            ):
                self.assertIsNone(windows_proxy.restore_stale_recovery(path))
            restore.assert_called_once_with(before)
            self.assertFalse(path.exists())

    def test_proxy_recovery_keeps_record_when_already_restored_cleanup_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "proxy_recovery.json"
            before = self.proxy_settings(ProxyEnable={"value": 0, "type": 4})
            applied = windows_proxy.build_local_proxy_settings(before, 8080)
            common.atomic_write_json(path, windows_proxy.make_recovery_state(before, applied, Path(tmp), 8080))
            real_unlink = Path.unlink

            def fail_recovery_unlink(candidate, *args, **kwargs):
                if candidate == path:
                    raise PermissionError("recovery locked")
                return real_unlink(candidate, *args, **kwargs)

            with (
                mock.patch.object(windows_proxy, "get_proxy_settings", return_value=before),
                mock.patch.object(windows_proxy, "apply_proxy_settings") as restore,
                mock.patch.object(Path, "unlink", fail_recovery_unlink),
            ):
                self.assertEqual(windows_proxy.restore_stale_recovery(path), "restored-kept")
            restore.assert_called_once_with(before)
            self.assertTrue(path.exists())

    def test_proxy_recovery_restores_safe_partial_ninja_capture_tool_transition(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "proxy_recovery.json"
            before = self.proxy_settings(ProxyEnable={"value": 0, "type": 4}, ProxyServer=None)
            applied = windows_proxy.build_local_proxy_settings(before, 8080)
            current = dict(applied)
            current["ProxyEnable"] = before["ProxyEnable"]
            common.atomic_write_json(path, windows_proxy.make_recovery_state(before, applied, Path(tmp), 8080))
            with (
                mock.patch.object(windows_proxy, "get_proxy_settings", side_effect=[current, before]),
                mock.patch.object(windows_proxy, "apply_proxy_settings") as restore,
            ):
                self.assertEqual(windows_proxy.restore_stale_recovery(path), "restored")
            restore.assert_called_once_with(before)
            self.assertFalse(path.exists())

    def test_proxy_restore_verifies_effective_windows_state_before_deleting_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "proxy_recovery.json"
            before = self.proxy_settings(ProxyEnable={"value": 0, "type": 4})
            applied = windows_proxy.build_local_proxy_settings(before, 8080)
            common.atomic_write_json(path, windows_proxy.make_recovery_state(before, applied, Path(tmp), 8080))
            mismatch = dict(applied)
            mismatch["ProxyServer"] = {"value": "127.0.0.1:9999", "type": 1}
            with (
                mock.patch.object(
                    windows_proxy,
                    "get_proxy_settings",
                    side_effect=[applied, mismatch, mismatch, mismatch, mismatch, mismatch],
                ),
                mock.patch.object(windows_proxy, "apply_proxy_settings") as restore,
                mock.patch.object(windows_proxy.time, "sleep"),
            ):
                with self.assertRaisesRegex(RuntimeError, r"did not retain the restored proxy settings .*ProxyServer"):
                    windows_proxy.restore_stale_recovery(path)
            restore.assert_called_once_with(before)
            self.assertTrue(path.exists())

    def test_deactivate_verifies_restoration_before_deleting_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "proxy_recovery.json"
            before = self.proxy_settings(ProxyEnable={"value": 0, "type": 4})
            applied = windows_proxy.build_local_proxy_settings(before, 8080)
            common.atomic_write_json(path, windows_proxy.make_recovery_state(before, applied, Path(tmp), 8080))
            with (
                mock.patch.object(windows_proxy, "get_proxy_settings", side_effect=[applied, before]),
                mock.patch.object(windows_proxy, "apply_proxy_settings") as restore,
            ):
                self.assertTrue(windows_proxy.deactivate_local_proxy(before, applied, path))
            restore.assert_called_once_with(before)
            self.assertFalse(path.exists())

    def test_deactivate_reports_recovery_cleanup_failure_separately_from_restore(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "proxy_recovery.json"
            path.write_text("owned", encoding="utf-8")
            before = self.proxy_settings(ProxyEnable={"value": 0, "type": 4})
            applied = windows_proxy.build_local_proxy_settings(before, 8080)
            real_unlink = Path.unlink

            def fail_recovery_unlink(candidate, *args, **kwargs):
                if candidate == path:
                    raise PermissionError("recovery locked")
                return real_unlink(candidate, *args, **kwargs)

            with (
                mock.patch.object(windows_proxy, "get_proxy_settings", side_effect=[applied, before]),
                mock.patch.object(windows_proxy, "apply_proxy_settings") as restore,
                mock.patch.object(Path, "unlink", fail_recovery_unlink),
            ):
                result = windows_proxy.deactivate_local_proxy(before, applied, path)
            self.assertTrue(result)
            self.assertEqual(result.recovery_cleanup_error, "recovery locked")
            restore.assert_called_once_with(before)
            self.assertTrue(path.exists())

    def test_activate_refuses_to_overwrite_unresolved_recovery_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "proxy_recovery.json"
            path.write_text("{}", encoding="utf-8")
            before = self.proxy_settings(ProxyEnable={"value": 0, "type": 4})
            with (
                mock.patch.object(windows_proxy, "apply_proxy_settings") as apply,
                self.assertRaisesRegex(RuntimeError, "Unresolved System Proxy recovery data already exists"),
            ):
                windows_proxy.activate_local_proxy(before, Path(tmp), 8080, path)
            apply.assert_not_called()
            self.assertEqual(path.read_text(encoding="utf-8"), "{}")

    def test_proxy_recovery_never_overwrites_external_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "proxy_recovery.json"
            before = self.proxy_settings(ProxyEnable={"value": 0, "type": 4})
            applied = windows_proxy.build_local_proxy_settings(before, 8080)
            external = self.proxy_settings(ProxyEnable={"value": 1, "type": 4}, ProxyServer={"value": "vpn.proxy:9999", "type": 1})
            common.atomic_write_json(path, windows_proxy.make_recovery_state(before, applied, Path(tmp), 8080))
            with (
                mock.patch.object(windows_proxy, "get_proxy_settings", return_value=external),
                mock.patch.object(windows_proxy, "apply_proxy_settings") as restore,
            ):
                result = windows_proxy.restore_stale_recovery(path)
            restore.assert_not_called()
            self.assertTrue(result.startswith("unowned:"))
            self.assertFalse(path.exists())
            self.assertTrue(Path(result.split(":", 1)[1]).exists())

    def test_deactivate_refuses_to_overwrite_external_proxy_change(self) -> None:
        before = self.proxy_settings(ProxyEnable={"value": 0, "type": 4})
        applied = windows_proxy.build_local_proxy_settings(before, 8080)
        external = self.proxy_settings(ProxyEnable={"value": 1, "type": 4}, ProxyServer={"value": "vpn.proxy:9999", "type": 1})
        with (
            mock.patch.object(windows_proxy, "get_proxy_settings", return_value=external),
            mock.patch.object(windows_proxy, "apply_proxy_settings") as restore,
        ):
            self.assertFalse(windows_proxy.deactivate_local_proxy(before, applied))
        restore.assert_not_called()

    def test_capture_startup_recovers_proxy_before_config_and_automatic_update(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, capture_mode="local", output_root=Path("output"), output_path=None)
        order: list[str] = []

        def load_startup(args):
            order.append("config")
            return dict(nct_config.DEFAULT_CONFIG), "signature", options

        def recover():
            order.append("recovery")

        def update_check(args, argv, configured_auto_update):
            order.append("update")
            return 0

        with (
            mock.patch.object(nct.sys, "platform", "win32"),
            mock.patch.object(elevation, "is_elevated", return_value=True),
            mock.patch.object(elevation, "elevation_task_is_current", return_value=True),
            mock.patch.object(nct, "capture_lock", side_effect=contextlib.nullcontext),
            mock.patch.object(nct, "_restore_interrupted_system_proxy", side_effect=recover),
            mock.patch.object(nct, "_load_startup_config_and_options", side_effect=load_startup),
            mock.patch.object(nct_config, "clean_duplicate_config_processes", return_value=(0, None)),
            mock.patch.object(nct_runtime, "show_console_window"),
            mock.patch.object(nct_runtime, "set_console_title"),
            mock.patch.object(nct_runtime, "ensure_local_capture_compatible"),
            mock.patch.object(nct, "handle_automatic_update", side_effect=update_check),
        ):
            self.assertEqual(nct.main([]), 0)
        self.assertEqual(order, ["recovery", "config", "update"])

    def test_system_proxy_capture_reveals_compiled_console_before_update_check(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, capture_mode="system-proxy", output_root=Path("output"), output_path=None)
        with (
            mock.patch.object(nct.sys, "platform", "win32"),
            mock.patch.object(nct_config, "load_stable_config_snapshot", return_value=(dict(nct_config.DEFAULT_CONFIG), None)),
            mock.patch.object(nct_config, "resolve_runtime_options", return_value=options),
            mock.patch.object(elevation, "is_elevated", return_value=True),
            mock.patch.object(elevation, "elevation_task_is_current", return_value=True),
            mock.patch.object(nct, "capture_lock", side_effect=contextlib.nullcontext),
            mock.patch.object(update, "TEMP_ROOT", Path(tempfile.gettempdir()) / "nct-test-update-temp"),
            mock.patch.object(nct_runtime, "show_console_window") as show_console,
            mock.patch.object(nct, "handle_automatic_update", return_value=0) as handle_update,
        ):
            self.assertEqual(nct.main([]), 0)
        show_console.assert_called_once()
        handle_update.assert_called_once()

    def test_mitmproxy_ca_generation_uses_the_configured_confdir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            confdir = Path(tmp)
            certificate = confdir / "mitmproxy-ca-cert.cer"
            private_ca = confdir / "mitmproxy-ca.pem"
            calls = []

            class FakeCertStore:
                @classmethod
                def from_store(cls, **kwargs):
                    calls.append(kwargs)
                    certificate.write_bytes(b"generated-certificate")
                    private_ca.write_bytes(b"generated-certificate")
                    return object()

            fake_mitmproxy = ModuleType("mitmproxy")
            fake_mitmproxy.certs = SimpleNamespace(CertStore=FakeCertStore)
            fake_mitmproxy.options = SimpleNamespace(KEY_SIZE=2048)
            with (
                mock.patch.object(common, "mitmproxy_conf_directory", return_value=confdir),
                mock.patch.dict(sys.modules, {"mitmproxy": fake_mitmproxy}),
            ):
                self.assertEqual(nct_runtime.ensure_mitmproxy_ca_exists(), certificate)
            self.assertEqual(calls, [{"path": confdir, "basename": "mitmproxy", "key_size": 2048}])

    def test_mitmproxy_ca_generation_rejects_partial_shared_ca(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            confdir = Path(tmp)
            (confdir / "mitmproxy-ca-cert.cer").write_bytes(b"certificate-without-private-ca")
            with mock.patch.object(common, "mitmproxy_conf_directory", return_value=confdir):
                with self.assertRaisesRegex(RuntimeError, "shared HTTPS certificate files are incomplete or inconsistent"):
                    nct_runtime.ensure_mitmproxy_ca_exists()

    def test_mitmproxy_ca_generation_rejects_mismatched_public_and_private_ca_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            confdir = Path(tmp)
            certificate = confdir / "mitmproxy-ca-cert.cer"
            private_ca = confdir / "mitmproxy-ca.pem"
            certificate.write_bytes(b"public-ca-a")
            private_ca.write_bytes(b"private-ca-b")
            with mock.patch.object(common, "mitmproxy_conf_directory", return_value=confdir):
                with self.assertRaisesRegex(RuntimeError, "incomplete or inconsistent") as raised:
                    nct_runtime.ensure_mitmproxy_ca_exists()
            self.assertIn("--remove-https-certificate", str(raised.exception))

    def test_mitmproxy_ca_trust_status_reports_incomplete_shared_ca(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            confdir = Path(tmp)
            certificate = confdir / "mitmproxy-ca-cert.cer"
            certificate.write_bytes(b"certificate-without-private-ca")
            with (
                mock.patch.object(nct_runtime.sys, "platform", "win32"),
                mock.patch.object(common, "mitmproxy_conf_directory", return_value=confdir),
                mock.patch.object(nct_runtime, "_certificate_is_trusted_in_root_store") as trusted,
            ):
                self.assertEqual(nct_runtime.mitmproxy_ca_trust_status(), ("incomplete", certificate))
            trusted.assert_not_called()

    def test_runtime_requires_expected_mitmproxy_version(self) -> None:
        with mock.patch.object(common.importlib.metadata, "version", return_value=common.MITMPROXY_VERSION):
            self.assertEqual(common.validate_mitmproxy_installation(), common.MITMPROXY_VERSION)
        with mock.patch.object(common.importlib.metadata, "version", return_value="0.0.0"):
            with self.assertRaisesRegex(RuntimeError, re.escape(common.MITMPROXY_VERSION)):
                common.validate_mitmproxy_installation()

    def test_mitmproxy_rs_fallback_is_version_specific(self) -> None:
        distribution = mock.Mock()
        distribution.metadata = {"Name": "mitmproxy-rs"}
        distribution.version = "0.12.12"
        distribution.files = []
        self.assertEqual(build_release.fallback_license_files(distribution), [])

    def test_update_cli_aliases_do_not_break_upstream_proxy_short_option(self) -> None:
        parser = nct_config.build_argument_parser()
        self.assertTrue(parser.parse_args(["-a"]).auto_update)
        self.assertTrue(parser.parse_args(["-n"]).no_auto_update)
        self.assertTrue(parser.parse_args(["-U"]).check_update)
        self.assertEqual(parser.parse_args(["-u", "direct"]).upstream_proxy, "direct")
