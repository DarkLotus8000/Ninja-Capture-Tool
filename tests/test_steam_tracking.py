# Run from the project root with: py -B -m unittest discover -s tests
from support import *

class SteamTrackingTests(NctTestBase):
    def test_warframe_version_state_round_trip_and_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "warframe_version.json"
            steam_tracking.save_warframe_version_high_water("43.5.4", checked_at="2026-09-11T09:50:00+02:00", path=path)
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(steam_tracking.load_warframe_version_high_water(path), "43.5.4")
            self.assertNotIn("source", data)
            self.assertNotIn("format_version", data)
            self.assertEqual(data["high_water_observed_at"], "2026-09-11T09:50:00+02:00")
            self.assertNotIn("awaiting_content_branch", data)
            self.assertNotIn("pre_transition_manifest_id", data)
            data["high_water_version"] = "U43.5.4"
            path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "Invalid Warframe version state"):
                steam_tracking.load_warframe_version_high_water(path)

    def test_steam_appinfo_v41_reports_valid_and_empty_manifest_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "appinfo.vdf"
            path.write_bytes(make_steam_appinfo_v41(4895911296145320793, 52 * 1024**3, 30 * 1024**3))
            valid = steam_tracking.read_steam_cached_public_manifest(path)
            self.assertEqual(valid["manifest_id"], 4895911296145320793)
            self.assertEqual(valid["status"], "valid")
            self.assertEqual(valid["size"], 52 * 1024**3)

            path.write_bytes(make_steam_appinfo_v41(5112463999164762556, 0, 0))
            empty = steam_tracking.read_steam_cached_public_manifest(path)
            self.assertEqual(empty["manifest_id"], 5112463999164762556)
            self.assertEqual(empty["status"], "invalid")

    def test_steam_manifest_zero_download_is_invalid_even_with_nonzero_size(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "appinfo.vdf"
            path.write_bytes(make_steam_appinfo_v41(5112463999164762556, 52 * 1024**3, 0))
            info = steam_tracking.read_steam_cached_public_manifest(path)
        self.assertEqual(info["status"], "invalid")

    def test_steam_manifest_smaller_than_ten_gib_is_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "appinfo.vdf"
            path.write_bytes(make_steam_appinfo_v41(123456789, 10 * 1024**3 - 1, 5 * 1024**3))
            info = steam_tracking.read_steam_cached_public_manifest(path)
        self.assertEqual(info["status"], "invalid")

    def test_direct_steam_live_query_does_not_require_desktop_client(self) -> None:
        token_modes: list[bool] = []

        class FakeSteamClient:
            def __init__(self):
                self.logged_on = False
                self.disconnected = False

            def anonymous_login(self):
                self.logged_on = True
                return 1

            def get_product_info(self, apps, timeout, auto_access_tokens=True):
                self.asserted_apps = apps
                self.asserted_timeout = timeout
                token_modes.append(auto_access_tokens)
                return {
                    "apps": {
                        steam_tracking.WARFRAME_STEAM_APP_ID: {
                            "depots": {
                                str(steam_tracking.WARFRAME_STEAM_DEPOT_ID): {
                                    "manifests": {
                                        "public": {
                                            "gid": "4895911296145320793",
                                            "size": str(52 * 1024**3),
                                            "download": str(30 * 1024**3),
                                        }
                                    }
                                }
                            },
                            "_change_number": 123,
                            "_missing_token": False,
                        }
                    }
                }

            def logout(self):
                self.logged_on = False

            def disconnect(self):
                self.disconnected = True

        steam_package = ModuleType("steam")
        steam_package.__path__ = []
        steam_client = ModuleType("steam.client")
        steam_client.SteamClient = FakeSteamClient
        with mock.patch.dict(sys.modules, {"steam": steam_package, "steam.client": steam_client}):
            info = steam_tracking.query_steam_public_manifest(timeout=4)
        self.assertEqual(info["manifest_id"], 4895911296145320793)
        self.assertEqual(info["status"], "valid")
        self.assertEqual(info["source_kind"], "live")
        self.assertEqual(set(info), {"manifest_id", "size", "status", "source_kind"})
        self.assertEqual(token_modes, [False])

    def test_direct_steam_live_query_requests_access_token_only_when_required(self) -> None:
        token_modes: list[bool] = []

        class FakeSteamClient:
            logged_on = False

            def anonymous_login(self):
                self.logged_on = True
                return 1

            def get_product_info(self, apps, timeout, auto_access_tokens=True):
                token_modes.append(auto_access_tokens)
                if not auto_access_tokens:
                    return {"apps": {steam_tracking.WARFRAME_STEAM_APP_ID: {"_missing_token": True}}}
                return {
                    "apps": {
                        steam_tracking.WARFRAME_STEAM_APP_ID: {
                            "depots": {
                                str(steam_tracking.WARFRAME_STEAM_DEPOT_ID): {
                                    "manifests": {
                                        "public": {
                                            "gid": "4895911296145320793",
                                            "size": str(52 * 1024**3),
                                            "download": str(30 * 1024**3),
                                        }
                                    }
                                }
                            },
                            "_missing_token": False,
                        }
                    }
                }

            def logout(self):
                self.logged_on = False

            def disconnect(self):
                pass

        steam_package = ModuleType("steam")
        steam_package.__path__ = []
        steam_client = ModuleType("steam.client")
        steam_client.SteamClient = FakeSteamClient
        with mock.patch.dict(sys.modules, {"steam": steam_package, "steam.client": steam_client}):
            info = steam_tracking.query_steam_public_manifest(timeout=4)
        self.assertEqual(info["manifest_id"], 4895911296145320793)
        self.assertEqual(token_modes, [False, True])

    def test_direct_steam_live_query_reports_failing_stage(self) -> None:
        class FakeSteamClient:
            logged_on = False

            def anonymous_login(self):
                raise OSError("socket test failure")

            def disconnect(self):
                pass

        steam_package = ModuleType("steam")
        steam_package.__path__ = []
        steam_client = ModuleType("steam.client")
        steam_client.SteamClient = FakeSteamClient
        with mock.patch.dict(sys.modules, {"steam": steam_package, "steam.client": steam_client}):
            with self.assertRaisesRegex(RuntimeError, "anonymous login: socket test failure"):
                steam_tracking.query_steam_public_manifest(timeout=4)

    def test_steam_worker_stage_parser_returns_latest_stage(self) -> None:
        output = (
            f"{steam_tracking.STEAM_QUERY_STAGE_PREFIX}anonymous login\n"
            "incidental output\n"
            f"{steam_tracking.STEAM_QUERY_STAGE_PREFIX}public product info\n"
        )
        self.assertEqual(steam_tracking.latest_steam_query_worker_stage(output), "public product info")

    def test_start_warframe_query_subprocess_uses_thirty_second_timeout_and_parent_death_job(self) -> None:
        process = mock.Mock()
        with (
            mock.patch.object(subprocess, "Popen", return_value=process) as popen,
            mock.patch.object(steam_tracking, "_attach_steam_worker_kill_job") as attach,
        ):
            result = steam_tracking.start_warframe_query_subprocess(entry_script=Path(nct.__file__))
        self.assertIs(result, process)
        attach.assert_called_once_with(process)
        command = popen.call_args.args[0]
        self.assertEqual(command[-2:], [steam_tracking.WARFRAME_QUERY_WORKER_ARGUMENT, "30"])

    def test_hidden_warframe_query_worker_rejects_malformed_internal_arguments(self) -> None:
        for arguments in (
            ["--internal-warframe-query-worker"],
            ["--internal-warframe-query-worker", "not-a-number"],
            ["--internal-warframe-query-worker", "0"],
            ["--internal-warframe-query-worker", "61"],
        ):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = steam_tracking.handle_warframe_query_worker_request(arguments)
            self.assertEqual(result, 2)
            line = output.getvalue().strip()
            self.assertTrue(line.startswith(steam_tracking.WARFRAME_QUERY_RESULT_PREFIX))
            payload = json.loads(line[len(steam_tracking.WARFRAME_QUERY_RESULT_PREFIX):])
            self.assertFalse(payload["ok"])

    def test_start_steam_query_subprocess_attaches_parent_death_job(self) -> None:
        process = mock.Mock()
        with (
            mock.patch.object(subprocess, "Popen", return_value=process),
            mock.patch.object(steam_tracking, "_attach_steam_worker_kill_job") as attach,
        ):
            result = steam_tracking.start_steam_query_subprocess(timeout=4, entry_script=Path(nct.__file__))
        self.assertIs(result, process)
        attach.assert_called_once_with(process)

    def test_start_steam_query_subprocess_continues_when_parent_death_job_is_unavailable(self) -> None:
        process = mock.Mock()
        with (
            mock.patch.object(subprocess, "Popen", return_value=process),
            mock.patch.object(steam_tracking, "_attach_steam_worker_kill_job", side_effect=OSError(5, "job denied")),
        ):
            result = steam_tracking.start_steam_query_subprocess(timeout=4, entry_script=Path(nct.__file__))
        self.assertIs(result, process)
        process.kill.assert_not_called()

    def test_hidden_steam_query_worker_rejects_malformed_internal_arguments(self) -> None:
        for arguments in (
            ["--internal-steam-query-worker"],
            ["--internal-steam-query-worker", "not-a-number"],
            ["--internal-steam-query-worker", "0"],
            ["--internal-steam-query-worker", "61"],
        ):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = steam_tracking.handle_steam_query_worker_request(arguments)
            self.assertEqual(result, 2)
            line = output.getvalue().strip()
            self.assertTrue(line.startswith(steam_tracking.STEAM_QUERY_RESULT_PREFIX))
            payload = json.loads(line[len(steam_tracking.STEAM_QUERY_RESULT_PREFIX):])
            self.assertFalse(payload["ok"])

    def test_hidden_steam_query_worker_smoke_mode_imports_dependency_without_network(self) -> None:
        steam_package = ModuleType("steam")
        steam_package.__path__ = []
        steam_client = ModuleType("steam.client")
        steam_client.SteamClient = object
        output = io.StringIO()
        with (
            mock.patch.dict(sys.modules, {"steam": steam_package, "steam.client": steam_client}),
            contextlib.redirect_stdout(output),
        ):
            result = steam_tracking.handle_steam_query_worker_request([steam_tracking.STEAM_QUERY_WORKER_SMOKE_ARGUMENT])
        self.assertEqual(result, 0)
        line = output.getvalue().strip()
        self.assertTrue(line.startswith(steam_tracking.STEAM_QUERY_RESULT_PREFIX))
        payload = json.loads(line[len(steam_tracking.STEAM_QUERY_RESULT_PREFIX):])
        self.assertEqual(payload, {"ok": True, "smoke": "steam-import"})

    def test_hidden_steam_query_worker_returns_json_result(self) -> None:
        info = {
            "manifest_id": 123,
            "size": 52 * 1024**3,
            "status": "valid",
            "source_kind": "live",
        }
        output = io.StringIO()
        with (
            mock.patch.object(steam_tracking, "query_steam_public_manifest", return_value=info),
            contextlib.redirect_stdout(output),
        ):
            result = steam_tracking.handle_steam_query_worker_request(["--internal-steam-query-worker", "4"])
        self.assertEqual(result, 0)
        line = output.getvalue().strip()
        self.assertTrue(line.startswith(steam_tracking.STEAM_QUERY_RESULT_PREFIX))
        payload = json.loads(line[len(steam_tracking.STEAM_QUERY_RESULT_PREFIX):])
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["info"]["manifest_id"], 123)

    def test_steam_worker_collector_ignores_noise_and_validates_tagged_schema(self) -> None:
        info = {
            "manifest_id": 123,
            "size": 52 * 1024**3,
            "status": "valid",
            "source_kind": "live",
        }

        class Process:
            returncode = 0
            def poll(self):
                return 0
            def communicate(self, timeout=None):
                payload = json.dumps({"ok": True, "info": info}, separators=(",", ":"))
                return f"incidental output\n{steam_tracking.STEAM_QUERY_RESULT_PREFIX}{payload}\nmore output\n", None

        result, error = steam_tracking.collect_steam_query_subprocess(Process())
        self.assertIsNone(error)
        self.assertEqual(result["manifest_id"], 123)

    def test_steam_worker_collector_rejects_extra_info_fields_and_non_live_source(self) -> None:
        base = {
            "manifest_id": 123,
            "size": 52 * 1024**3,
            "status": "valid",
            "source_kind": "live",
        }

        class Process:
            returncode = 0
            def __init__(self, info):
                self.info = info
            def poll(self):
                return 0
            def communicate(self, timeout=None):
                payload = json.dumps({"ok": True, "info": self.info}, separators=(",", ":"))
                return steam_tracking.STEAM_QUERY_RESULT_PREFIX + payload + "\n", None

        extra = dict(base, unexpected="value")
        result, error = steam_tracking.collect_steam_query_subprocess(Process(extra))
        self.assertIsNone(result)
        self.assertIn("invalid info schema", error)

        wrong_source = dict(base, source_kind="cache")
        result, error = steam_tracking.collect_steam_query_subprocess(Process(wrong_source))
        self.assertIsNone(result)
        self.assertIn("unexpected source kind", error)

    def test_steam_live_query_falls_back_to_labeled_local_cache(self) -> None:
        cached = {
            "manifest_id": 123,
            "size": 52 * 1024**3,
            "status": "valid",
            "source_kind": "cache",
        }
        with mock.patch.object(steam_tracking, "read_steam_cached_public_manifest", return_value=cached):
            info, error = steam_tracking.steam_manifest_with_cache_fallback(None, "Steam offline")
        self.assertIsNone(error)
        self.assertEqual(info["source_kind"], "cache")
        self.assertEqual(info["live_error"], "Steam offline")

    def test_live_tracking_state_preserves_steam_wait_and_pre_transition_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "warframe_version.json"
            steam_tracking.save_warframe_version_high_water("44.0", path=path)
            steam_tracking.save_steam_tracking_state(
                last_valid_steam_manifest_id=843737746734465482,
                last_valid_steam_manifest_size=53 * 1024**3,
                awaiting_content_branch="44.0",
                awaiting_from_manifest_id=843737746734465482,
                pre_transition_manifest_id=843737746734465482,
                pre_transition_manifest_size=53 * 1024**3,
                pre_transition_content_branch="43.5",
                high_water_version="44.0",
                path=path,
            )
            state = steam_tracking.load_live_tracking_state(path)
        self.assertEqual(state["high_water_version"], "44.0")
        self.assertEqual(state["last_valid_steam_manifest_id"], 843737746734465482)
        self.assertEqual(state["awaiting_content_branch"], "44.0")
        self.assertEqual(state["awaiting_from_manifest_id"], 843737746734465482)
        self.assertEqual(state["pre_transition_manifest_id"], 843737746734465482)
        self.assertNotIn("pre_transition_from_manifest_id", state)
        self.assertEqual(state["pre_transition_content_branch"], "43.5")

    def test_live_tracking_state_uses_same_invariants_for_load_and_save(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            load_path = root / "invalid-load.json"
            load_path.write_text(
                json.dumps(
                    {
                        "high_water_version": "43.5.4",
                        "last_valid_steam_manifest_id": 123,
                        "last_valid_steam_manifest_size": None,
                        "awaiting_content_branch": None,
                        "awaiting_from_manifest_id": None,
                        "pre_transition_manifest_id": None,
                        "pre_transition_manifest_size": None,
                        "pre_transition_content_branch": None,
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RuntimeError, "Saved valid Steam manifest is missing its installed size"):
                steam_tracking.load_live_tracking_state(load_path)
            with self.assertRaisesRegex(ValueError, "Saved valid Steam manifest is missing its installed size"):
                steam_tracking.save_steam_tracking_state(
                    last_valid_steam_manifest_id=123,
                    last_valid_steam_manifest_size=None,
                    awaiting_content_branch=None,
                    awaiting_from_manifest_id=None,
                    high_water_version="43.5.4",
                    path=root / "invalid-save.json",
                )

    def test_content_update_persists_pending_steam_wait_with_new_high_water_immediately(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None)
        session = nct.CaptureSession(options)
        session.steam_tracking_state_loaded = True
        session.last_valid_steam_manifest_id = 111
        session.last_valid_steam_manifest_size = 52 * 1024**3
        with (
            mock.patch.object(live_tracking, "load_warframe_version_high_water", return_value="43.5.4"),
            mock.patch.object(live_tracking, "save_steam_tracking_state") as save_steam_state,
            mock.patch.object(live_tracking, "save_warframe_version_high_water") as save_version,
        ):
            version_info, _ = session._apply_current_warframe_version_result(
                "44.0", None, announce_current=False
            )
        self.assertTrue(version_info["content_update"])
        self.assertEqual(session.awaiting_content_branch, "44.0")
        self.assertEqual(session.awaiting_from_manifest_id, 111)
        save_version.assert_not_called()
        save_steam_state.assert_called_once()
        kwargs = save_steam_state.call_args.kwargs
        self.assertEqual(kwargs["high_water_version"], "44.0")
        self.assertEqual(kwargs["awaiting_content_branch"], "44.0")
        self.assertEqual(kwargs["awaiting_from_manifest_id"], 111)

    def test_content_update_and_new_manifest_in_same_check_resolves_immediately(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None)
        session = nct.CaptureSession(options)
        session.steam_tracking_state_loaded = True
        session.last_valid_steam_manifest_id = 4895911296145320793
        session.last_valid_steam_manifest_size = 52 * 1024**3
        session.live_steam_manifest = live_tracking.SteamManifestObservation(4895911296145320793, "valid", 52 * 1024**3, "live")
        with (
            mock.patch.object(live_tracking, "load_warframe_version_high_water", return_value="43.5.4"),
            mock.patch.object(live_tracking, "save_warframe_version_high_water"),
        ):
            version_info, messages = session._apply_current_warframe_version_result(
                "44.0", None, announce_current=False
            )
        _, steam_messages = session._apply_current_steam_manifest_result(
            {
                "manifest_id": 843737746734465482,
                "size": 53 * 1024**3,
                "status": "valid",
                "source_kind": "live",
            },
            None,
            announce_current=False,
            content_update=bool(version_info["content_update"]),
        )
        messages.extend(steam_messages)
        self.assertTrue(version_info["content_update"])
        self.assertIsNone(session.awaiting_content_branch)
        self.assertEqual(session.last_valid_steam_manifest_id, 843737746734465482)
        self.assertIn(
            ("info", "[Steam] New original Steam manifest base available: 843737746734465482 (53.0 GiB)"),
            messages,
        )

    def test_pre_transition_manifest_is_preserved_and_marked_uncertain_after_branch_flip(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None)
        session = nct.CaptureSession(options)
        session.steam_tracking_state_loaded = True
        session.live_warframe_version = "43.5.4"
        session.last_valid_steam_manifest_id = 111
        session.last_valid_steam_manifest_size = 52 * 1024**3
        session.live_steam_manifest = live_tracking.SteamManifestObservation(111, "valid", 52 * 1024**3, "live")

        _, early_messages = session._apply_current_steam_manifest_result(
            {
                "manifest_id": 222,
                "size": 53 * 1024**3,
                "status": "valid",
                "source_kind": "live",
            },
            None,
            announce_current=False,
            content_update=False,
        )
        self.assertEqual(session.pre_transition_manifest_id, 222)
        self.assertEqual(session.pre_transition_content_branch, "43.5")
        self.assertTrue(any("pre-transition candidate" in message for _, message in early_messages))

        session.live_warframe_version = "44.0"
        _, transition_messages = session._apply_current_steam_manifest_result(
            {
                "manifest_id": 222,
                "size": 53 * 1024**3,
                "status": "valid",
                "source_kind": "live",
            },
            None,
            announce_current=False,
            content_update=True,
        )
        self.assertEqual(session.awaiting_content_branch, "44.0")
        self.assertEqual(session.awaiting_from_manifest_id, 222)
        self.assertTrue(any("association with the new content update is uncertain" in message for _, message in transition_messages))

        _, resolved_messages = session._apply_current_steam_manifest_result(
            {
                "manifest_id": 333,
                "size": 54 * 1024**3,
                "status": "valid",
                "source_kind": "live",
            },
            None,
            announce_current=False,
            content_update=False,
        )
        self.assertIsNone(session.awaiting_content_branch)
        self.assertIsNone(session.pre_transition_manifest_id)
        self.assertTrue(any("New original Steam manifest base available: 333" in message for _, message in resolved_messages))

    def test_content_update_requires_known_warframe_content_branch(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None)
        session = nct.CaptureSession(options)
        session.steam_tracking_state_loaded = True
        with self.assertRaisesRegex(RuntimeError, "known Warframe content branch"):
            session._apply_current_steam_manifest_result(
                {
                    "manifest_id": 843737746734465482,
                    "size": 53 * 1024**3,
                    "status": "valid",
                    "source_kind": "live",
                },
                None,
                announce_current=False,
                content_update=True,
            )

    def test_warframe_status_query_runs_off_main_control_loop(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None)
        session = nct.CaptureSession(options)
        process = FakeSteamQueryProcess(running=True)
        with mock.patch.object(live_tracking, "start_warframe_query_subprocess", return_value=process) as start:
            before = time.monotonic()
            session._start_warframe_status_query(announce_current=True)
            elapsed = time.monotonic() - before
        self.assertLess(elapsed, 0.25)
        self.assertIs(session.warframe_status_process, process)
        start.assert_called_once_with(timeout=30.0, entry_script=common.TOOL_DIR / "ninja_capture_tool.py")

    def test_warframe_status_watchdog_uses_cached_version_and_allows_replacement(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None)
        session = nct.CaptureSession(options)
        session.warframe_version_high_water = "43.5.4"
        first = FakeSteamQueryProcess(running=True)
        second = FakeSteamQueryProcess(running=False)
        with (
            mock.patch.object(live_tracking, "start_warframe_query_subprocess", side_effect=[first, second]),
            mock.patch.object(live_tracking, "terminate_warframe_query_subprocess") as terminate,
            mock.patch.object(live_tracking, "collect_warframe_query_subprocess", return_value=("43.5.4", None)),
            mock.patch.object(live_tracking, "_WARFRAME_STATUS_QUERY_DEADLINE_SECONDS", 0.01),
        ):
            session._start_warframe_status_query(announce_current=True)
            session.warframe_status_started_at = time.monotonic() - 1.0
            session._consume_warframe_status_result()
            terminate.assert_called_once_with(first)
            self.assertIsNone(session.warframe_status_process)
            self.assertEqual(
                session._current_warframe_status_line(),
                "[Warframe] Cached version: U43.5.4 — live query unavailable (query timed out).",
            )

            session._start_warframe_status_query(announce_current=False)
            self.assertIs(session.warframe_status_process, second)
            session._consume_warframe_status_result()

        self.assertEqual(session.live_warframe_version, "43.5.4")
        self.assertIsNone(session.live_warframe_error)

    def test_warframe_content_update_rechecks_steam_if_previous_query_already_finished(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None)
        session = nct.CaptureSession(options)
        session.warframe_status_process = FakeSteamQueryProcess(running=False)
        session.warframe_status_started_at = time.monotonic()
        session.warframe_status_checked_at = "2026-09-23T12:00:00+02:00"
        with (
            mock.patch.object(live_tracking, "collect_warframe_query_subprocess", return_value=("43.6", None)),
            mock.patch.object(live_tracking, "load_warframe_version_high_water", return_value="43.5.4"),
            mock.patch.object(session, "_start_steam_status_query") as start_steam,
        ):
            session._consume_warframe_status_result()
        start_steam.assert_called_once_with(announce_current=False, content_update=True)

    def test_steam_status_query_runs_off_main_control_loop(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None)
        session = nct.CaptureSession(options)
        process = FakeSteamQueryProcess(running=True)
        with mock.patch.object(live_tracking, "start_steam_query_subprocess", return_value=process) as start:
            before = time.monotonic()
            session._start_steam_status_query(announce_current=True, content_update=False)
            elapsed = time.monotonic() - before
        self.assertLess(elapsed, 0.25)
        self.assertIs(session.steam_status_process, process)
        start.assert_called_once_with(timeout=30.0, entry_script=common.TOOL_DIR / "ninja_capture_tool.py")

    def test_steam_status_watchdog_kills_timed_out_worker_and_allows_replacement(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None)
        session = nct.CaptureSession(options)
        session.steam_tracking_state_loaded = True
        first = FakeSteamQueryProcess(running=True)
        second = FakeSteamQueryProcess(running=False)
        with (
            mock.patch.object(live_tracking, "start_steam_query_subprocess", side_effect=[first, second]),
            mock.patch.object(live_tracking, "terminate_steam_query_subprocess") as terminate,
            mock.patch.object(
                live_tracking,
                "collect_steam_query_subprocess",
                return_value=(
                    {
                        "manifest_id": 222,
                        "size": 2048,
                        "status": "valid",
                        "source_kind": "live",
                    },
                    None,
                ),
            ),
            mock.patch.object(live_tracking, "steam_manifest_with_cache_fallback", side_effect=lambda info, error: (info, error)),
            mock.patch.object(live_tracking, "_STEAM_STATUS_QUERY_DEADLINE_SECONDS", 0.01),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            session._start_steam_status_query(announce_current=True, content_update=False)
            session.steam_status_started_at = time.monotonic() - 1.0
            session._consume_steam_status_result()
            terminate.assert_called_once_with(first)
            self.assertIsNone(session.steam_status_process)

            session._start_steam_status_query(announce_current=False, content_update=False)
            self.assertIs(session.steam_status_process, second)
            session._consume_steam_status_result()

        self.assertEqual(session.last_valid_steam_manifest_id, 222)

    def test_debug_steam_timeout_reports_latest_worker_stage_in_one_line(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None, debug=True)
        session = nct.CaptureSession(options)
        session.steam_tracking_state_loaded = True
        process = FakeSteamQueryProcess(running=True)

        def cache_fallback(info, error):
            if info is not None:
                return info, None
            return ({
                "manifest_id": 4895911296145320793,
                "size": 52 * 1024**3,
                "status": "valid",
                "source_kind": "cache",
                "live_error": error,
            }, None)

        worker_output = f"{steam_tracking.STEAM_QUERY_STAGE_PREFIX}anonymous login\n"
        with (
            mock.patch.object(live_tracking, "start_steam_query_subprocess", return_value=process),
            mock.patch.object(live_tracking, "terminate_steam_query_subprocess", return_value=worker_output),
            mock.patch.object(live_tracking, "steam_manifest_with_cache_fallback", side_effect=cache_fallback),
            mock.patch.object(live_tracking, "_STEAM_STATUS_QUERY_DEADLINE_SECONDS", 0.01),
        ):
            session._start_steam_status_query(announce_current=False, content_update=False)
            session.steam_status_started_at = time.monotonic() - 1.0
            session._consume_steam_status_result()

        debug_lines = [line for line in session.pending_live_status_log_messages if line.startswith("[Debug] [Steam]")]
        self.assertEqual(len(debug_lines), 1)
        self.assertIn("timed out after 0.01 seconds during anonymous login", debug_lines[0])
        self.assertIn("using cached manifest 4895911296145320793 (52.0 GiB)", debug_lines[0])
        self.assertFalse(any("Direct live query failure detail" in line for line in session.pending_live_status_log_messages))

    def test_live_query_error_normalization_collapses_embedded_newlines(self) -> None:
        raw = "[WinError 10053] Eine bestehende Verbindung wurde softwaregesteuert\r\n\r\ndurch den Hostcomputer abgebrochen"
        self.assertEqual(
            steam_tracking.normalize_live_query_error(raw),
            "[WinError 10053] Eine bestehende Verbindung wurde softwaregesteuert durch den Hostcomputer abgebrochen",
        )
        self.assertEqual(steam_tracking.summarize_warframe_live_query_error(raw), "connection aborted locally")

    def test_non_debug_steam_failure_does_not_add_redundant_detail_log(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None, debug=False)
        session = nct.CaptureSession(options)
        session.live_status_header_initialized = True
        session.live_steam_manifest = live_tracking.SteamManifestObservation(123, "valid", 52 * 1024**3, "cache")
        session.live_steam_error = "query timed out"
        with mock.patch.object(session, "_set_live_status_line"):
            session._refresh_steam_status_header()
        self.assertFalse(any("Direct live query failure detail" in line for line in session.pending_live_status_log_messages))

    def test_steam_unavailable_status_is_header_only(self) -> None:
        self.assertTrue(live_tracking.LiveTrackingMixin._live_status_message_is_header_only(
            "[Steam] Live manifest unavailable (query timed out)."
        ))

    def test_steam_source_recovery_same_manifest_is_console_silent(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None)
        session = nct.CaptureSession(options)
        session.steam_tracking_state_loaded = True
        session.live_steam_manifest = live_tracking.SteamManifestObservation(123, "valid", 52 * 1024**3, "cache")
        session.last_valid_steam_manifest_id = 123
        session.last_valid_steam_manifest_size = 52 * 1024**3
        _, messages = session._apply_current_steam_manifest_result(
            {
                "manifest_id": 123,
                "size": 52 * 1024**3,
                "status": "valid",
                "source_kind": "live",
            },
            None,
            announce_current=False,
            content_update=False,
        )
        text = "\n".join(message for _, message in messages)
        self.assertNotIn("Direct live query recovered", text)
        self.assertNotIn("Live manifest changed", text)
        self.assertIn(
            "[Steam] Direct live query recovered; live manifest remains 123 (52.0 GiB).",
            session.pending_live_status_log_messages,
        )

    def test_steam_source_recovery_from_stale_different_cache_id_returns_to_accepted_manifest(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None)
        session = nct.CaptureSession(options)
        session.steam_tracking_state_loaded = True
        session.live_steam_manifest = live_tracking.SteamManifestObservation(999, "valid", 51 * 1024**3, "cache")
        session.last_valid_steam_manifest_id = 123
        session.last_valid_steam_manifest_size = 52 * 1024**3
        _, messages = session._apply_current_steam_manifest_result(
            {
                "manifest_id": 123,
                "size": 52 * 1024**3,
                "status": "valid",
                "source_kind": "live",
            },
            None,
            announce_current=False,
            content_update=False,
        )
        text = "\n".join(message for _, message in messages)
        self.assertNotIn("Direct live query recovered", text)
        self.assertNotIn("New live manifest candidate", text)
        self.assertNotIn("Live manifest changed", text)
        self.assertIn(
            "[Steam] Direct live query recovered; live manifest remains 123 (52.0 GiB).",
            session.pending_live_status_log_messages,
        )
        self.assertEqual(session.last_valid_steam_manifest_id, 123)
        self.assertIsNone(session.pre_transition_manifest_id)

    def test_steam_appinfo_cache_reuses_unchanged_file_and_refreshes_after_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "appinfo.vdf"
            path.write_bytes(make_steam_appinfo_v41(111, 1024, 512))
            first = steam_tracking.read_steam_cached_public_manifest(path)
            with mock.patch.object(Path, "read_bytes", wraps=Path.read_bytes) as read_bytes:
                second = steam_tracking.read_steam_cached_public_manifest(path)
                self.assertEqual(read_bytes.call_count, 0)
            self.assertEqual(first["manifest_id"], second["manifest_id"])

            time.sleep(0.002)
            path.write_bytes(make_steam_appinfo_v41(222, 2048, 1024))
            refreshed = steam_tracking.read_steam_cached_public_manifest(path)
            self.assertEqual(refreshed["manifest_id"], 222)

    def test_warframe_version_request_disables_intermediary_caching(self) -> None:
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            @staticmethod
            def geturl():
                return steam_tracking.WARFRAME_VERSION_URL

            @staticmethod
            def read(size):
                return b"43.5.4\n"

        opener = mock.MagicMock()
        opener.open.return_value = Response()
        with mock.patch.object(steam_tracking.urllib.request, "build_opener", return_value=opener):
            self.assertEqual(steam_tracking.fetch_current_warframe_version(), "43.5.4")
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 30.0)
        request = opener.open.call_args.args[0]
        headers = {key.casefold(): value for key, value in request.header_items()}
        self.assertEqual(headers["accept"], "text/plain")
        self.assertEqual(headers["cache-control"], "no-cache")
        self.assertEqual(headers["pragma"], "no-cache")

    def test_warframe_version_check_warns_on_backwards_value_without_persisting_it(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None)
        session = nct.CaptureSession(options)
        with (
            mock.patch.object(live_tracking, "load_warframe_version_high_water", return_value="43.5.5"),
            mock.patch.object(live_tracking, "save_warframe_version_high_water") as save,
        ):
            info, messages = session._apply_current_warframe_version_result(
                "43.5.4", None, announce_current=True
            )
        self.assertEqual(info["version"], "43.5.4")
        self.assertEqual(info["status"], "backwards")
        self.assertEqual(info["previous_version"], "43.5.5")
        self.assertIn(("warning", "Reported Warframe version changed backwards: U43.5.5 -> U43.5.4"), messages)
        self.assertNotIn(("info", "[Warframe] New version detected: U43.5.5 -> U43.5.4"), messages)
        save.assert_not_called()

    def test_warframe_version_equivalent_numeric_forms_are_not_reported_as_changes(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None)
        session = nct.CaptureSession(options)
        with (
            mock.patch.object(live_tracking, "load_warframe_version_high_water", return_value="43.5.1"),
            mock.patch.object(live_tracking, "save_warframe_version_high_water") as save,
        ):
            info, messages = session._apply_current_warframe_version_result(
                "43.5.1.0", None, announce_current=True
            )
        self.assertEqual(info["status"], "current")
        self.assertEqual(info["previous_version"], "43.5.1")
        self.assertFalse(any("New version detected" in message for _, message in messages))
        self.assertFalse(any("changed backwards" in message for _, message in messages))
        save.assert_not_called()

    def test_warframe_version_check_reports_change_and_persists_new_value(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None)
        session = nct.CaptureSession(options)
        with (
            mock.patch.object(live_tracking, "load_warframe_version_high_water", return_value="43.5.4"),
            mock.patch.object(live_tracking, "save_warframe_version_high_water") as save,
        ):
            info, messages = session._apply_current_warframe_version_result(
                "43.5.5", None, announce_current=True
            )
        self.assertEqual(info["version"], "43.5.5")
        self.assertEqual(info["status"], "newer")
        self.assertEqual(info["previous_version"], "43.5.4")
        self.assertIn(("info", "[Warframe] Live version: U43.5.5"), messages)
        save.assert_called_once()
        self.assertEqual(save.call_args.args[0], "43.5.5")

    def test_in_memory_high_water_survives_state_save_failure_and_rejects_stale_followup(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None)
        session = nct.CaptureSession(options)
        with (
            mock.patch.object(live_tracking, "load_warframe_version_high_water", side_effect=["43.5.4", "43.5.4"]),
            mock.patch.object(live_tracking, "save_warframe_version_high_water", side_effect=OSError("disk full")) as save,
        ):
            first_info, first_messages = session._apply_current_warframe_version_result(
                "43.5.5", None, announce_current=True
            )
            second_info, second_messages = session._apply_current_warframe_version_result(
                "43.5.4", None, announce_current=True
            )
        self.assertEqual(first_info["status"], "newer")
        self.assertEqual(first_info["previous_version"], "43.5.4")
        self.assertEqual(session.warframe_version_high_water, "43.5.5")
        self.assertIn(("warning", "Could not save the current Warframe version state: disk full"), first_messages)
        self.assertEqual(second_info["status"], "backwards")
        self.assertEqual(second_info["previous_version"], "43.5.5")
        self.assertIn(("warning", "Reported Warframe version changed backwards: U43.5.5 -> U43.5.4"), second_messages)
        save.assert_called_once()

    def test_failed_high_water_save_is_retried_when_same_version_is_reported_again(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None)
        session = nct.CaptureSession(options)
        with (
            mock.patch.object(live_tracking, "load_warframe_version_high_water", side_effect=["43.5.4", "43.5.4"]),
            mock.patch.object(
                live_tracking,
                "save_warframe_version_high_water",
                side_effect=[OSError("disk full"), None],
            ) as save,
        ):
            first_info, first_messages = session._apply_current_warframe_version_result(
                "43.5.5", None, announce_current=True
            )
            second_info, second_messages = session._apply_current_warframe_version_result(
                "43.5.5", None, announce_current=True
            )
        self.assertEqual(first_info["status"], "newer")
        self.assertEqual(first_info["previous_version"], "43.5.4")
        self.assertEqual(second_info["status"], "current")
        self.assertEqual(second_info["previous_version"], "43.5.5")
        self.assertEqual(session.warframe_version_high_water, "43.5.5")
        self.assertIn(("warning", "Could not save the current Warframe version state: disk full"), first_messages)
        self.assertFalse(any(severity == "warning" for severity, _ in second_messages))
        self.assertEqual(save.call_count, 2)
        self.assertEqual([call.args[0] for call in save.call_args_list], ["43.5.5", "43.5.5"])

    def test_debug_logs_successful_warframe_live_check_in_one_line(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None, debug=True)
        session = nct.CaptureSession(options)
        session.warframe_status_process = FakeSteamQueryProcess(running=False)
        session.warframe_status_started_at = time.monotonic()
        session.warframe_status_checked_at = "2026-09-23T12:00:00+02:00"
        with mock.patch.object(live_tracking, "collect_warframe_query_subprocess", return_value=("43.5.4", None)):
            session._consume_warframe_status_result()
        debug_lines = [line for line in session.pending_live_status_log_messages if line.startswith("[Debug] [Warframe]")]
        self.assertEqual(len(debug_lines), 1)
        self.assertRegex(debug_lines[0], r"^\[Debug\] \[Warframe\] Live check succeeded in \d+\.\d{2}s: U43\.5\.4$")

    def test_debug_classifies_warframe_tls_handshake_timeout(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None, debug=True)
        session = nct.CaptureSession(options)
        error = "_ssl.c:1064: The handshake operation timed out"
        session.warframe_status_process = FakeSteamQueryProcess(running=False)
        session.warframe_status_started_at = time.monotonic()
        session.warframe_status_checked_at = "2026-09-23T12:00:00+02:00"
        with mock.patch.object(live_tracking, "collect_warframe_query_subprocess", return_value=(None, error)):
            session._consume_warframe_status_result()
        debug_lines = [line for line in session.pending_live_status_log_messages if line.startswith("[Debug] [Warframe]")]
        self.assertEqual(len(debug_lines), 1)
        self.assertIn("TLS handshake timed out", debug_lines[0])
        self.assertIn(error, debug_lines[0])
        self.assertEqual(session._current_warframe_status_line(), "[Warframe] Live version unavailable (TLS handshake timed out).")

    def test_rotation_uses_last_known_warframe_version_without_blocking_on_live_query(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            current = common.create_session_directory(root)
            options = dict(
                nct_config.DEFAULT_CONFIG,
                output_root=root,
                output_path=None,
                name_session_after_warframe_version=True,
            )
            session = nct.CaptureSession(options)
            session.session_root = current
            version_info = {
                "version": "43.5.5",
                "checked_at": None,
                "status": "cached",
                "previous_version": "43.5.5",
                "content_update": False,
            }
            messages: list[tuple[str, str]] = []
            with (
                mock.patch.object(
                    session,
                    "_current_warframe_version_snapshot",
                    return_value=(version_info, messages),
                ) as snapshot,
                mock.patch.object(session, "_start_warframe_status_query") as start_query,
            ):
                pending = session._prepare_rotation_target("")
            snapshot.assert_called_once_with()
            start_query.assert_called_once_with(announce_current=False)
            self.assertEqual(Path(pending["session_root"]).name, "43.5.5")
            self.assertEqual(pending["warframe_version_messages"], messages)
            manifest = common.read_json_object(Path(pending["manifest_path"]))
            self.assertEqual(manifest["warframe_version"], "43.5.5")
            self.assertEqual(manifest["warframe_version_status"], "cached")
            self.assertEqual(manifest["session_naming"], "warframe_version")

    def test_session_manifest_records_advisory_warframe_version_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp) / "43.5.4"
            session.mkdir()
            version_info = {
                "version": "43.5.4",
                "checked_at": "2026-09-11T09:50:00+02:00",
                "status": "backwards",
                "previous_version": "43.5.5",
            }
            capture.initialize_session_manifest(
                session,
                dict(nct_config.DEFAULT_CONFIG, output_root=Path(tmp), output_path=None),
                self.manifest_path_for(session),
                warframe_version_info=version_info,
            )
            data = json.loads(self.manifest_path_for(session).read_text(encoding="utf-8"))
            self.assertEqual(data["warframe_version"], "43.5.4")
            self.assertEqual(data["warframe_version_checked_at"], "2026-09-11T09:50:00+02:00")
            self.assertEqual(data["warframe_version_status"], "backwards")
            self.assertEqual(data["warframe_version_previous"], "43.5.5")
            self.assertEqual(data["session_naming"], "timestamp")

    def test_warframe_cached_status_matches_steam_fallback_format(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None)
        session = nct.CaptureSession(options)
        session.warframe_version_high_water = "43.5.4"
        session.live_warframe_error = "[Errno 11001] getaddrinfo failed"
        self.assertEqual(
            session._current_warframe_status_line(),
            "[Warframe] Cached version: U43.5.4 — live query unavailable (DNS lookup failed).",
        )

    def test_live_status_header_uses_cached_warframe_version_while_async_check_is_pending(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None)
        session = nct.CaptureSession(options)
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            session._initialize_live_status_header({"version": "43.5.4", "status": "cached"})
        self.assertEqual(
            stdout.getvalue().splitlines(),
            [
                "[Warframe] Cached version: U43.5.4 — checking live version...",
                "[Steam] Checking live manifest...",
            ],
        )

    def test_live_status_header_prints_steam_immediately_after_warframe(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None)
        session = nct.CaptureSession(options)
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            session._initialize_live_status_header({"version": "43.5.4"})
        self.assertEqual(
            stdout.getvalue().splitlines(),
            ["[Warframe] Live version: U43.5.4", "[Steam] Checking live manifest..."],
        )

    def test_live_status_header_rewrites_existing_console_row_when_possible(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None)
        session = nct.CaptureSession(options)
        session.live_status_header_initialized = True
        session.live_status_rows["steam"] = 12
        session.live_status_texts["steam"] = "[Steam] Checking live manifest..."
        stdout = io.StringIO()
        try:
            with (
                mock.patch.object(nct_runtime, "rewrite_console_status_row", return_value=7) as rewrite,
                contextlib.redirect_stdout(stdout),
            ):
                session._set_live_status_line("steam", "[Steam] Live manifest: 123 (52.0 GiB)")
                deadline = time.monotonic() + 1.0
                while rewrite.call_count == 0 and time.monotonic() < deadline:
                    time.sleep(0.01)
            rewrite.assert_called_once_with(12, "[Steam] Checking live manifest...", "[Steam] Live manifest: 123 (52.0 GiB)")
            self.assertEqual(session.live_status_rows["steam"], 7)
            self.assertEqual(stdout.getvalue(), "")
        finally:
            session._stop_worker_console_dispatcher(timeout=1.0)

    def test_live_status_update_does_not_block_control_loop_when_console_is_busy(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None)
        session = nct.CaptureSession(options)
        session.live_status_header_initialized = True
        session.live_status_rows["steam"] = 12
        session.live_status_texts["steam"] = "[Steam] Checking live manifest..."
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(nct_runtime, "rewrite_console_status_row", return_value=12):
            session.logger = nct_session.SessionLogger(Path(tmp) / "capture.log")
            assert session.logger is not None
            session.logger.console_lock.acquire()
            try:
                session._set_live_status_line("steam", "[Steam] Live manifest: 111 (52.0 GiB)")
                deadline = time.monotonic() + 1.0
                while not session.worker_console_rendering and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(session.worker_console_rendering)

                before = time.monotonic()
                session._set_live_status_line("steam", "[Steam] Live manifest: 222 (52.0 GiB)")
                elapsed = time.monotonic() - before
                self.assertLess(elapsed, 0.25)
                self.assertEqual(
                    session.pending_live_status_updates.get("steam"),
                    "[Steam] Live manifest: 222 (52.0 GiB)",
                )
            finally:
                session.logger.console_lock.release()

            deadline = time.monotonic() + 1.0
            while (
                session.live_status_texts.get("steam") != "[Steam] Live manifest: 222 (52.0 GiB)"
                and time.monotonic() < deadline
            ):
                time.sleep(0.01)
            self.assertEqual(session.live_status_texts.get("steam"), "[Steam] Live manifest: 222 (52.0 GiB)")
            session._stop_worker_console_dispatcher(timeout=1.0)
            session.logger.close()

    def test_live_status_row_relocates_after_console_reflow(self) -> None:
        expected = "[Steam] Checking live manifest..."
        replacement = "[Steam] Live manifest: 4895911296145320793 (52.6 GiB)"
        rows = {3: expected, 7: "Capture is active. Start the Warframe Launcher or Warframe to capture downloaded assets."}
        writes: list[tuple[int, str]] = []

        class Function:
            def __init__(self, callback):
                self.callback = callback
                self.argtypes = None
                self.restype = None

            def __call__(self, *args):
                return self.callback(*args)

        class Kernel32:
            def __init__(self):
                self.GetConsoleScreenBufferInfo = Function(self.get_info)
                self.ReadConsoleOutputCharacterW = Function(self.read_row)
                self.FillConsoleOutputCharacterW = Function(lambda *args: self.set_count(args[-1], args[2]))
                self.FillConsoleOutputAttribute = Function(lambda *args: self.set_count(args[-1], args[2]))
                self.WriteConsoleOutputCharacterW = Function(self.write_row)
                self.SetConsoleCursorPosition = Function(lambda *args: 1)

            @staticmethod
            def set_count(pointer, count):
                pointer._obj.value = int(count)
                return 1

            @staticmethod
            def get_info(handle, pointer):
                info = pointer._obj
                info.dwSize.X = 160
                info.dwSize.Y = 100
                info.dwCursorPosition.X = 0
                info.dwCursorPosition.Y = 10
                info.wAttributes = 7
                info.srWindow.Top = 0
                info.srWindow.Bottom = 20
                return 1

            @staticmethod
            def read_row(handle, buffer, width, origin, pointer):
                value = rows.get(int(origin.Y), "")
                padded = value.ljust(int(width))
                buffer.value = padded
                pointer._obj.value = int(width)
                return 1

            @staticmethod
            def write_row(handle, text, length, origin, pointer):
                writes.append((int(origin.Y), text[: int(length)]))
                pointer._obj.value = int(length)
                return 1

        fake_stdout = SimpleNamespace(isatty=lambda: True, fileno=lambda: 1)
        fake_msvcrt = SimpleNamespace(get_osfhandle=lambda fd: 123)
        with (
            mock.patch.object(nct_runtime.sys, "platform", "win32"),
            mock.patch.object(nct_runtime.sys, "stdout", fake_stdout),
            mock.patch.dict(sys.modules, {"msvcrt": fake_msvcrt}),
            mock.patch.object(nct_runtime.ctypes, "WinDLL", return_value=Kernel32(), create=True),
        ):
            relocated = nct_runtime.rewrite_console_status_row(7, expected, replacement)
        self.assertEqual(relocated, 3)
        self.assertEqual(writes, [(3, replacement)])

    def test_live_status_header_does_not_track_a_row_that_would_wrap(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None)
        session = nct.CaptureSession(options)
        session.live_status_header_initialized = True
        stdout = io.StringIO()
        long_line = "[Steam] " + "x" * 200
        with (
            mock.patch.object(nct_runtime, "console_status_row", return_value=None) as status_row,
            contextlib.redirect_stdout(stdout),
        ):
            session._set_live_status_line("steam", long_line, initial=True)
        status_row.assert_called_once_with(long_line)
        self.assertIsNone(session.live_status_rows["steam"])

    def test_cached_steam_header_reports_concise_dependency_failure_reason(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None)
        session = nct.CaptureSession(options)
        session.live_steam_manifest = live_tracking.SteamManifestObservation(4895911296145320793, "valid", 52 * 1024**3, "cache")
        session.live_steam_error = f"pysteam-client[client] {common.STEAM_CLIENT_VERSION} is required for live Steam manifest queries"
        self.assertEqual(
            session._current_steam_status_line(),
            "[Steam] Cached manifest: 4895911296145320793 (52.0 GiB) — live query unavailable (Steam client dependency missing).",
        )

    def test_live_to_cached_fallback_uses_status_header_without_redundant_console_message(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None)
        session = nct.CaptureSession(options)
        session.steam_tracking_state_loaded = True
        session.live_steam_manifest = live_tracking.SteamManifestObservation(
            4895911296145320793, "valid", 52 * 1024**3, "live"
        )
        session.last_valid_steam_manifest_id = 4895911296145320793
        session.last_valid_steam_manifest_size = 52 * 1024**3

        _, messages = session._apply_current_steam_manifest_result(
            {
                "manifest_id": 4895911296145320793,
                "size": 52 * 1024**3,
                "status": "valid",
                "source_kind": "cache",
                "live_error": "query timed out",
            },
            None,
            announce_current=False,
            content_update=False,
        )

        self.assertEqual(messages, [])
        self.assertEqual(
            session._current_steam_status_line(),
            "[Steam] Cached manifest: 4895911296145320793 (52.0 GiB) — live query unavailable (query timed out).",
        )

    def test_cached_manifest_candidate_wording_is_consistent_between_messages_and_header(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None)
        session = nct.CaptureSession(options)
        session.steam_tracking_state_loaded = True
        _, messages = session._apply_current_steam_manifest_result(
            {
                "manifest_id": 5112463999164762556,
                "size": 0,
                "status": "invalid",
                "source_kind": "cache",
                "live_error": f"pysteam-client[client] {common.STEAM_CLIENT_VERSION} is required for live Steam manifest queries",
            },
            None,
            announce_current=True,
            content_update=False,
        )
        expected = (
            "[Steam] Cached manifest candidate: 5112463999164762556 (invalid) — "
            "live query unavailable (Steam client dependency missing)."
        )
        self.assertIn(("info", expected), messages)
        self.assertEqual(session._current_steam_status_line(), expected)

    def test_steam_tracking_updates_preserve_high_water_observation_timestamp(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "warframe_version.json"
            observed = "2026-09-14T10:00:00+02:00"
            steam_tracking.save_warframe_version_high_water("43.5.4", checked_at=observed, path=path)
            steam_tracking.save_steam_tracking_state(
                last_valid_steam_manifest_id=4895911296145320793,
                last_valid_steam_manifest_size=52 * 1024**3,
                awaiting_content_branch=None,
                awaiting_from_manifest_id=None,
                high_water_version="43.5.4",
                path=path,
            )
            state = common.read_json_object(path)
        self.assertEqual(state["high_water_observed_at"], observed)

    def test_steam_app_info_rejects_present_but_malformed_numeric_metadata(self) -> None:
        def app_data(size: object, download: object) -> dict[str, object]:
            return {
                "depots": {
                    "230411": {
                        "manifests": {
                            "public": {"gid": "123", "size": size, "download": download}
                        }
                    }
                }
            }
        with self.assertRaisesRegex(RuntimeError, "manifest size"):
            steam_tracking._steam_manifest_from_app_data(app_data("broken", 1), source_kind="live")
        with self.assertRaisesRegex(RuntimeError, "download size"):
            steam_tracking._steam_manifest_from_app_data(app_data(52 * 1024**3, -1), source_kind="live")

    def test_uncertain_pre_transition_wording_survives_direct_query_recovery(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None)
        session = nct.CaptureSession(options)
        session.steam_tracking_state_loaded = True
        session.live_warframe_version = "44.0"
        session.awaiting_content_branch = "44.0"
        session.awaiting_from_manifest_id = 222
        session.pre_transition_manifest_id = 222
        session.pre_transition_manifest_size = 53 * 1024**3
        session.pre_transition_content_branch = "43.5"
        session.live_steam_manifest = live_tracking.SteamManifestObservation(222, "valid", 53 * 1024**3, "cache")
        _, messages = session._apply_current_steam_manifest_result(
            {
                "manifest_id": 222,
                "size": 53 * 1024**3,
                "status": "valid",
                "source_kind": "live",
            },
            None,
            announce_current=False,
            content_update=False,
        )
        self.assertTrue(any("recovered; pre-transition manifest candidate 222" in message and "still uncertain" in message for _, message in messages))
