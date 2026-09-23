# Run from the project root with: py -B -m unittest discover -s tests
from support import *

class ElevationTests(NctTestBase):
    def test_live_system_proxy_to_local_restarts_subsystem_without_elevation_handoff(self) -> None:
        args = nct_config.build_argument_parser().parse_args([])
        initial = dict(nct_config.DEFAULT_CONFIG)
        initial["capture_mode"] = "system-proxy"
        options = nct_config.resolve_runtime_options(args, initial)
        session = nct.CaptureSession(options, cli_args=args)
        config = dict(nct_config.DEFAULT_CONFIG)
        output = io.StringIO()
        with (
            mock.patch.object(nct.sys, "platform", "win32"),
            mock.patch.object(elevation, "is_elevated", return_value=True),
            mock.patch.object(session, "_restart_capture_subsystem") as restart_subsystem,
            contextlib.redirect_stdout(output),
        ):
            self.assertFalse(session._apply_reloaded_config(config))
        restart_subsystem.assert_called_once()
        self.assertIsNone(session.end_reason)
        self.assertNotIn("administrator privileges", output.getvalue())

    def test_non_elevated_runtime_uses_uac_when_task_is_missing_before_config_load(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None)
        with (
            mock.patch.object(nct.sys, "platform", "win32"),
            mock.patch.object(nct, "handle_early_update_request", return_value=None),
            mock.patch.object(nct_config, "load_stable_config_snapshot", return_value=(dict(nct_config.DEFAULT_CONFIG), None)) as load_config,
            mock.patch.object(nct_config, "resolve_runtime_options", return_value=options),
            mock.patch.object(elevation, "is_elevated", return_value=False),
            mock.patch.object(nct, "another_capture_is_active", return_value=False) as active,
            mock.patch.object(elevation, "elevation_task_is_current", return_value=False) as current,
            mock.patch.object(elevation, "run_elevated_and_wait", return_value=0) as elevate,
            mock.patch.object(elevation, "launch_via_elevation_task") as task_launch,
            mock.patch.object(nct_runtime, "show_console_window") as show_console,
            mock.patch.object(nct, "handle_automatic_update") as handle_update,
        ):
            self.assertEqual(nct.main(["--capture-mode", "system-proxy"]), 0)
        active.assert_called_once_with()
        current.assert_called_once_with()
        elevate.assert_called_once_with(["--capture-mode", "system-proxy"], show_window=True)
        task_launch.assert_not_called()
        load_config.assert_not_called()
        show_console.assert_not_called()
        handle_update.assert_not_called()

    def test_non_elevated_runtime_propagates_direct_uac_exit_code_when_task_is_missing(self) -> None:
        with (
            mock.patch.object(nct.sys, "platform", "win32"),
            mock.patch.object(nct, "handle_early_update_request", return_value=None),
            mock.patch.object(elevation, "is_elevated", return_value=False),
            mock.patch.object(nct, "another_capture_is_active", return_value=False),
            mock.patch.object(elevation, "elevation_task_is_current", return_value=False),
            mock.patch.object(elevation, "run_elevated_and_wait", return_value=7) as elevate,
            mock.patch.object(elevation, "launch_via_elevation_task") as task_launch,
        ):
            self.assertEqual(nct.main([]), 7)
        elevate.assert_called_once_with([], show_window=True)
        task_launch.assert_not_called()

    def test_non_elevated_runtime_uses_existing_task_without_uac(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None)
        with (
            mock.patch.object(nct.sys, "platform", "win32"),
            mock.patch.object(nct, "handle_early_update_request", return_value=None),
            mock.patch.object(nct_config, "load_stable_config_snapshot", return_value=(dict(nct_config.DEFAULT_CONFIG), None)),
            mock.patch.object(nct_config, "resolve_runtime_options", return_value=options),
            mock.patch.object(elevation, "is_elevated", return_value=False),
            mock.patch.object(nct, "another_capture_is_active", return_value=False),
            mock.patch.object(elevation, "elevation_task_is_current", return_value=True),
            mock.patch.object(elevation, "launch_via_elevation_task") as task_launch,
            mock.patch.object(elevation, "run_elevated_and_wait") as elevate,
            mock.patch.object(nct_runtime, "show_console_window") as show_console,
        ):
            self.assertEqual(nct.main(["-o", "U43.5.4"]), 0)
        task_launch.assert_called_once_with(["-o", "U43.5.4"])
        elevate.assert_not_called()
        show_console.assert_not_called()

    def test_non_elevated_runtime_falls_back_to_uac_when_current_task_cannot_start(self) -> None:
        stderr = io.StringIO()
        with (
            mock.patch.object(nct.sys, "platform", "win32"),
            mock.patch.object(nct, "handle_early_update_request", return_value=None),
            mock.patch.object(elevation, "is_elevated", return_value=False),
            mock.patch.object(nct, "another_capture_is_active", return_value=False),
            mock.patch.object(elevation, "elevation_task_is_current", return_value=True),
            mock.patch.object(
                elevation,
                "launch_via_elevation_task",
                side_effect=RuntimeError("task did not acknowledge startup"),
            ) as task_launch,
            mock.patch.object(elevation, "run_elevated_and_wait", return_value=0) as elevate,
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(nct.main(["-m", "local"]), 0)
        task_launch.assert_called_once_with(["-m", "local"])
        elevate.assert_called_once_with(["-m", "local"], show_window=True)
        self.assertIn("falling back to UAC", stderr.getvalue())

    def test_elevated_runtime_defers_task_install_message_to_session_startup(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None)
        session = mock.MagicMock()
        with (
            mock.patch.object(nct.sys, "platform", "win32"),
            mock.patch.object(nct, "handle_early_update_request", return_value=None),
            mock.patch.object(nct_config, "load_stable_config_snapshot", return_value=(dict(nct_config.DEFAULT_CONFIG), None)),
            mock.patch.object(nct_config, "resolve_runtime_options", return_value=options),
            mock.patch.object(elevation, "is_elevated", return_value=True),
            mock.patch.object(elevation, "elevation_task_is_current", return_value=False),
            mock.patch.object(elevation, "install_elevation_task") as install_task,
            mock.patch.object(nct_runtime, "show_console_window"),
            mock.patch.object(nct, "capture_lock"),
            mock.patch.object(nct, "handle_automatic_update", return_value=None),
            mock.patch.object(nct, "validate_mitmproxy_installation"),
            mock.patch.object(nct, "validate_windows_capture_package"),
            mock.patch.object(nct, "CaptureSession", return_value=session) as capture_session,
            mock.patch.object(nct.atexit, "register"),
            mock.patch.object(nct, "install_termination_handlers"),
        ):
            self.assertEqual(nct.main([]), 0)
        install_task.assert_called_once_with()
        capture_session.assert_called_once_with(options, ["Elevation task installed successfully."])
        session.start.assert_called_once_with()

    def test_elevated_runtime_continues_when_task_install_fails(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None)
        session = mock.MagicMock()
        with (
            mock.patch.object(nct.sys, "platform", "win32"),
            mock.patch.object(nct, "handle_early_update_request", return_value=None),
            mock.patch.object(nct_config, "load_stable_config_snapshot", return_value=(dict(nct_config.DEFAULT_CONFIG), None)),
            mock.patch.object(nct_config, "resolve_runtime_options", return_value=options),
            mock.patch.object(elevation, "is_elevated", return_value=True),
            mock.patch.object(elevation, "elevation_task_is_current", return_value=False),
            mock.patch.object(
                elevation,
                "install_elevation_task",
                side_effect=RuntimeError("Task Scheduler rejected the task"),
            ) as install_task,
            mock.patch.object(nct_runtime, "show_console_window"),
            mock.patch.object(nct, "capture_lock"),
            mock.patch.object(nct, "handle_automatic_update", return_value=None),
            mock.patch.object(nct, "validate_mitmproxy_installation"),
            mock.patch.object(nct, "validate_windows_capture_package"),
            mock.patch.object(nct, "CaptureSession", return_value=session) as capture_session,
            mock.patch.object(nct.atexit, "register"),
            mock.patch.object(nct, "install_termination_handlers"),
        ):
            self.assertEqual(nct.main([]), 0)
        install_task.assert_called_once_with()
        setup_messages = capture_session.call_args.args[1]
        self.assertEqual(len(setup_messages), 1)
        self.assertIn("future launches may require UAC", setup_messages[0])
        self.assertIn("Task Scheduler rejected the task", setup_messages[0])
        session.start.assert_called_once_with()

    def test_remove_elevation_task_reports_specific_success_message(self) -> None:
        stdout = io.StringIO()
        with (
            mock.patch.object(nct.sys, "platform", "win32"),
            mock.patch.object(nct, "handle_early_update_request", return_value=None),
            mock.patch.object(elevation, "elevation_task_exists", return_value=True),
            mock.patch.object(elevation, "is_elevated", return_value=True),
            mock.patch.object(elevation, "remove_elevation_task", return_value=True),
            mock.patch.object(nct_runtime, "show_console_window"),
            contextlib.redirect_stdout(stdout),
        ):
            self.assertEqual(nct.main(["--remove-elevation-task"]), 0)
        self.assertEqual(stdout.getvalue(), "Elevation task removed successfully.\n")

    def test_remove_elevation_task_reports_specific_not_installed_message(self) -> None:
        stdout = io.StringIO()
        with (
            mock.patch.object(nct.sys, "platform", "win32"),
            mock.patch.object(nct, "handle_early_update_request", return_value=None),
            mock.patch.object(elevation, "elevation_task_exists", return_value=False),
            mock.patch.object(elevation, "remove_elevation_task", return_value=False) as remove_task,
            mock.patch.object(nct_runtime, "show_console_window"),
            contextlib.redirect_stdout(stdout),
        ):
            self.assertEqual(nct.main(["--remove-elevation-task"]), 0)
        self.assertEqual(stdout.getvalue(), "Elevation task is not installed.\n")
        remove_task.assert_called_once_with()

    def test_remove_elevation_task_waits_for_elevated_completion(self) -> None:
        with (
            mock.patch.object(nct.sys, "platform", "win32"),
            mock.patch.object(nct, "handle_early_update_request", return_value=None),
            mock.patch.object(elevation, "elevation_task_exists", return_value=True),
            mock.patch.object(elevation, "is_elevated", return_value=False),
            mock.patch.object(elevation, "run_elevated_and_wait", return_value=0) as elevate,
            mock.patch.object(nct_runtime, "show_console_window"),
        ):
            self.assertEqual(nct.main(["--remove-elevation-task"]), 0)
        elevate.assert_called_once_with(["--remove-elevation-task"], show_window=True)

    def test_remove_elevation_task_must_be_standalone_and_short_form_keeps_error_visible(self) -> None:
        stderr = io.StringIO()
        with (
            mock.patch.object(nct.sys, "platform", "win32"),
            mock.patch.object(nct_runtime, "show_console_window") as show_console,
            contextlib.redirect_stderr(stderr),
        ):
            with self.assertRaises(SystemExit):
                nct.main(["-r", "-m", "local"])
        show_console.assert_called_once_with()
        self.assertIn("--remove-elevation-task must be used without other arguments", stderr.getvalue())

    def test_current_windows_user_id_uses_locale_independent_sid(self) -> None:
        output = b'"DOMAIN\\User","S-1-5-21-100-200-300-1001"\r\n'
        with (
            mock.patch.object(elevation.sys, "platform", "win32"),
            mock.patch.object(
                nct.subprocess,
                "run",
                return_value=SimpleNamespace(returncode=0, stdout=output),
            ) as run,
        ):
            self.assertEqual(elevation._current_windows_user_id(), "S-1-5-21-100-200-300-1001")
        self.assertEqual(run.call_args.args[0], ["whoami", "/user", "/fo", "csv", "/nh"])

    def test_elevation_task_install_uses_isolated_on_demand_task_with_required_settings(self) -> None:
        calls = []
        captured_xml: bytes | None = None

        def fake_run(command, **kwargs):
            nonlocal captured_xml
            calls.append(command)
            if command[:2] == ["schtasks", "/Create"]:
                xml_path = Path(command[command.index("/XML") + 1])
                captured_xml = xml_path.read_bytes()
            return SimpleNamespace(returncode=0, stdout=b"")

        with (
            mock.patch.object(elevation.sys, "platform", "win32"),
            mock.patch.object(elevation, "is_elevated", return_value=True),
            mock.patch.object(elevation, "_current_windows_user_id", return_value="S-1-5-21-1-2-3-1001"),
            mock.patch.object(elevation, "elevation_task_is_current", return_value=True),
            mock.patch.object(elevation, "_query_elevation_task", return_value=None),
            mock.patch.object(elevation, "_cleanup_stale_elevation_tasks", return_value=0) as cleanup_stale,
            mock.patch.object(elevation.subprocess, "run", side_effect=fake_run),
        ):
            elevation.install_elevation_task()
        cleanup_stale.assert_called_once_with("S-1-5-21-1-2-3-1001")

        self.assertEqual(len(calls), 1)
        create = calls[0]
        self.assertEqual(create[:2], ["schtasks", "/Create"])
        self.assertEqual(
            create[create.index("/TN") + 1],
            elevation._elevation_task_path("S-1-5-21-1-2-3-1001"),
        )
        self.assertIn("/XML", create)
        self.assertNotIn("/SC", create)
        self.assertNotIn("/SD", create)
        self.assertNotIn("/ST", create)
        self.assertIsNotNone(captured_xml)

        root = ET.fromstring(captured_xml)
        self.assertEqual(elevation._task_xml_value(root, "UserId"), "S-1-5-21-1-2-3-1001")
        self.assertEqual(elevation._task_xml_value(root, "RunLevel"), "HighestAvailable")
        self.assertEqual(elevation._task_xml_value(root, "LogonType"), "InteractiveToken")
        triggers = next(element for element in root.iter() if element.tag.rsplit("}", 1)[-1] == "Triggers")
        self.assertEqual(list(triggers), [])
        self.assertEqual(elevation._task_xml_bool(root, "DisallowStartIfOnBatteries"), False)
        self.assertEqual(elevation._task_xml_bool(root, "StopIfGoingOnBatteries"), False)
        self.assertEqual(elevation._task_xml_bool(root, "AllowStartOnDemand"), True)
        self.assertEqual(elevation._task_xml_value(root, "ExecutionTimeLimit"), "PT0S")
        self.assertEqual(elevation._task_xml_value(root, "WorkingDirectory"), str(common.TOOL_DIR.resolve()))

    def test_internal_elevation_task_install_only_installs_and_exits(self) -> None:
        with (
            mock.patch.object(nct.sys, "platform", "win32"),
            mock.patch.object(elevation, "is_elevated", return_value=True),
            mock.patch.object(elevation, "install_elevation_task") as install,
            mock.patch.object(nct_config, "load_stable_config_snapshot") as load_config,
        ):
            self.assertEqual(nct.main([elevation.INSTALL_ELEVATION_TASK_ARGUMENT]), 0)
        install.assert_called_once_with()
        load_config.assert_not_called()

    def test_elevation_task_run_acknowledges_before_config_load_and_passes_install_message(self) -> None:
        options = dict(nct_config.DEFAULT_CONFIG, output_root=Path("output"), output_path=None)
        session = mock.MagicMock()
        events: list[str] = []

        request_id = "a" * 32

        def acknowledge_request(value: str, *, status: str = "started") -> None:
            self.assertEqual(value, request_id)
            self.assertEqual(status, "started")
            events.append("ack-request")

        def load_config(*args, **kwargs):
            events.append("load-config")
            return dict(nct_config.DEFAULT_CONFIG), None

        with (
            mock.patch.object(nct.sys, "platform", "win32"),
            mock.patch.object(elevation, "is_elevated", return_value=True),
            mock.patch.object(elevation, "consume_elevation_request", return_value=([], True, request_id)),
            mock.patch.object(nct_config, "load_stable_config_snapshot", side_effect=load_config),
            mock.patch.object(nct_config, "resolve_runtime_options", return_value=options),
            mock.patch.object(nct_runtime, "show_console_window"),
            mock.patch.object(nct, "capture_lock"),
            mock.patch.object(elevation, "acknowledge_elevation_request", side_effect=acknowledge_request),
            mock.patch.object(nct, "handle_automatic_update", return_value=None),
            mock.patch.object(nct, "validate_mitmproxy_installation"),
            mock.patch.object(nct, "validate_windows_capture_package"),
            mock.patch.object(nct, "CaptureSession", return_value=session) as capture_session,
            mock.patch.object(nct.atexit, "register"),
            mock.patch.object(nct, "install_termination_handlers"),
        ):
            self.assertEqual(nct.main([elevation.ELEVATION_TASK_RUN_ARGUMENT]), 0)
        self.assertLess(events.index("ack-request"), events.index("load-config"))
        capture_session.assert_called_once_with(options, ["Elevation task installed successfully."])
        session.start.assert_called_once_with()

    def test_elevation_task_capture_lock_conflict_clears_request_without_console(self) -> None:
        @contextlib.contextmanager
        def conflicting_lock():
            raise nct.CaptureBusyError("Another Ninja Capture Tool capture is already running.")
            yield

        options = dict(
            nct_config.DEFAULT_CONFIG,
            capture_mode="local",
            output_root=Path("output"),
            output_path=None,
        )
        with (
            mock.patch.object(nct.sys, "platform", "win32"),
            mock.patch.object(elevation, "is_elevated", return_value=True),
            mock.patch.object(elevation, "consume_elevation_request", return_value=([], False, "b" * 32)),
            mock.patch.object(nct_config, "load_stable_config_snapshot", return_value=(dict(nct_config.DEFAULT_CONFIG), None)),
            mock.patch.object(nct_config, "resolve_runtime_options", return_value=options),
            mock.patch.object(nct, "capture_lock", side_effect=conflicting_lock),
            mock.patch.object(elevation, "acknowledge_elevation_request") as acknowledge_request,
            mock.patch.object(nct_runtime, "show_console_window") as show_console,
        ):
            self.assertEqual(nct.main([elevation.ELEVATION_TASK_RUN_ARGUMENT]), 0)
        acknowledge_request.assert_called_once_with("b" * 32, status="busy")
        show_console.assert_not_called()

    def test_elevation_task_request_is_not_acknowledged_until_capture_lock_is_acquired(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            request = root / ".elevation-request.json"
            ack = root / f".elevation-ack-{'c' * 32}.json"
            request_id = "c" * 32
            request.write_text(
                json.dumps({
                    "schema_version": elevation.ELEVATION_HANDOFF_SCHEMA_VERSION,
                    "request_id": request_id,
                    "created_at_unix": time.time(),
                    "argv": ["-o", "capture"],
                    "task_installed": True,
                }),
                encoding="utf-8",
            )
            with (
                mock.patch.object(elevation, "_elevation_request_file", return_value=request),
                mock.patch.object(elevation, "_elevation_ack_file", return_value=ack),
            ):
                self.assertEqual(elevation.consume_elevation_request(), (["-o", "capture"], True, request_id))
                self.assertTrue(request.exists())
                self.assertFalse(ack.exists())
                elevation.acknowledge_elevation_request(request_id)
                self.assertTrue(request.exists())
                self.assertEqual(elevation._matching_elevation_ack(request_id), ("started", None))

    def _current_task_xml(
        self,
        *,
        user_id: str = "S-1-5-21-1-2-3-1001",
        command: str | None = None,
        arguments: str | None = None,
        working_directory: str | None = None,
        run_level: str = "HighestAvailable",
        logon_type: str = "InteractiveToken",
        multiple_instances_policy: str = "IgnoreNew",
        disallow_start_if_on_batteries: str = "false",
        stop_if_going_on_batteries: str = "false",
        allow_hard_terminate: str = "true",
        start_when_available: str = "false",
        run_only_if_network_available: str = "false",
        allow_start_on_demand: str = "true",
        enabled: str = "true",
        hidden: str = "false",
        run_only_if_idle: str = "false",
        wake_to_run: str = "false",
        execution_time_limit: str = "PT0S",
        priority: str = "7",
        trigger_xml: str = "",
    ) -> bytes:
        expected_command, expected_arguments = elevation._task_action()
        command = expected_command if command is None else command
        arguments = expected_arguments if arguments is None else arguments
        working_directory = str(common.TOOL_DIR.resolve()) if working_directory is None else working_directory
        return f"""<?xml version='1.0' encoding='UTF-8'?>
<Task xmlns='http://schemas.microsoft.com/windows/2004/02/mit/task'>
  <Triggers>{trigger_xml}</Triggers>
  <Settings>
    <MultipleInstancesPolicy>{multiple_instances_policy}</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>{disallow_start_if_on_batteries}</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>{stop_if_going_on_batteries}</StopIfGoingOnBatteries>
    <AllowHardTerminate>{allow_hard_terminate}</AllowHardTerminate>
    <StartWhenAvailable>{start_when_available}</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>{run_only_if_network_available}</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>{allow_start_on_demand}</AllowStartOnDemand>
    <Enabled>{enabled}</Enabled>
    <Hidden>{hidden}</Hidden>
    <RunOnlyIfIdle>{run_only_if_idle}</RunOnlyIfIdle>
    <WakeToRun>{wake_to_run}</WakeToRun>
    <ExecutionTimeLimit>{execution_time_limit}</ExecutionTimeLimit>
    <Priority>{priority}</Priority>
  </Settings>
  <Principals><Principal><UserId>{user_id}</UserId><LogonType>{logon_type}</LogonType><RunLevel>{run_level}</RunLevel></Principal></Principals>
  <Actions><Exec><Command>{command}</Command><Arguments>{arguments}</Arguments><WorkingDirectory>{working_directory}</WorkingDirectory></Exec></Actions>
</Task>""".encode("utf-8")

    def _task_validation_result(self, xml: bytes) -> bool:
        with (
            mock.patch.object(elevation.sys, "platform", "win32"),
            mock.patch.object(elevation, "_current_windows_user_id", return_value="S-1-5-21-1-2-3-1001"),
            mock.patch.object(elevation.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=xml)),
        ):
            return elevation.elevation_task_is_current()

    def test_elevation_task_validation_matches_current_action_and_required_settings(self) -> None:
        self.assertTrue(self._task_validation_result(self._current_task_xml()))

    def test_elevation_task_validation_rejects_different_windows_user(self) -> None:
        self.assertFalse(self._task_validation_result(self._current_task_xml(user_id="S-1-5-21-1-2-3-2002")))

    def test_elevation_task_validation_rejects_stale_install_path(self) -> None:
        self.assertFalse(
            self._task_validation_result(self._current_task_xml(command="C:/Old/NinjaCaptureTool.exe"))
        )

    def test_elevation_task_validation_rejects_stale_working_directory(self) -> None:
        self.assertFalse(
            self._task_validation_result(self._current_task_xml(working_directory="C:/Old/Ninja Capture Tool"))
        )

    def test_elevation_task_validation_accepts_normalized_nonessential_settings(self) -> None:
        for field, value in (
            ("multiple_instances_policy", "Parallel"),
            ("disallow_start_if_on_batteries", "true"),
            ("stop_if_going_on_batteries", "true"),
            ("allow_hard_terminate", "false"),
            ("start_when_available", "true"),
            ("run_only_if_network_available", "true"),
            ("hidden", "true"),
            ("run_only_if_idle", "true"),
            ("wake_to_run", "true"),
            ("execution_time_limit", "PT1H"),
            ("priority", "5"),
        ):
            with self.subTest(field=field):
                self.assertTrue(self._task_validation_result(self._current_task_xml(**{field: value})))

    def test_elevation_task_validation_rejects_unusable_or_triggered_task(self) -> None:
        for field, value in (
            ("allow_start_on_demand", "false"),
            ("enabled", "false"),
            ("trigger_xml", "<TimeTrigger><Enabled>true</Enabled></TimeTrigger>"),
        ):
            with self.subTest(field=field):
                self.assertFalse(self._task_validation_result(self._current_task_xml(**{field: value})))

    def test_elevation_task_validation_rejects_missing_required_settings(self) -> None:
        command, arguments = elevation._task_action()
        xml = f"""<Task>
<Principals><Principal><UserId>S-1-5-21-1-2-3-1001</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
<Actions><Exec><Command>{command}</Command><Arguments>{arguments}</Arguments><WorkingDirectory>{common.TOOL_DIR.resolve()}</WorkingDirectory></Exec></Actions></Task>""".encode("utf-8")
        self.assertFalse(self._task_validation_result(xml))

    def test_elevation_task_validation_rejects_non_elevated_task(self) -> None:
        self.assertFalse(self._task_validation_result(self._current_task_xml(run_level="LeastPrivilege")))

    def test_elevation_task_path_isolated_by_user_and_installation(self) -> None:
        user_a = "S-1-5-21-1-2-3-1001"
        user_b = "S-1-5-21-1-2-3-2002"
        with mock.patch.object(elevation, "TOOL_DIR", Path("C:/Ninja Capture Tool-A")):
            user_a_path = elevation._elevation_task_path(user_a)
            user_b_path = elevation._elevation_task_path(user_b)
        with mock.patch.object(elevation, "TOOL_DIR", Path("D:/Ninja Capture Tool-B")):
            other_install_path = elevation._elevation_task_path(user_a)

        self.assertNotEqual(user_a_path, user_b_path)
        self.assertNotEqual(user_a_path, other_install_path)
        self.assertTrue(user_a_path.startswith("\\Ninja Capture Tool "))
        self.assertEqual(len(user_a_path.removeprefix("\\Ninja Capture Tool ")), 16)

    def test_elevation_task_listing_accepts_only_nct_hash_tasks(self) -> None:
        output = (
            "Ninja Capture Tool 0123456789abcdef\r\n"
            "Ninja Capture Tool FEDCBA9876543210\r\n"
            "Ninja Capture Tool not-a-hash\r\n"
            "Other Task\r\n"
        ).encode("utf-8")
        with mock.patch.object(
            elevation.subprocess,
            "run",
            return_value=SimpleNamespace(returncode=0, stdout=output),
        ) as run:
            self.assertEqual(
                elevation._list_nct_elevation_tasks(),
                [
                    r"\Ninja Capture Tool 0123456789abcdef",
                    r"\Ninja Capture Tool FEDCBA9876543210",
                ],
            )
        command = run.call_args.args[0]
        self.assertEqual(command[:4], ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command"])

    def test_stale_task_cleanup_removes_only_missing_compiled_installation_for_same_user(self) -> None:
        user_id = "S-1-5-21-1-2-3-1001"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing_install = root / "old-nct"
            existing_install = root / "existing-nct"
            existing_install.mkdir()

            def compiled_task(install: Path) -> ET.Element:
                with (
                    mock.patch.object(elevation, "TOOL_DIR", install),
                    mock.patch.object(elevation.sys, "frozen", True, create=True),
                    mock.patch.object(elevation.sys, "executable", str(install / "NinjaCaptureTool.exe")),
                ):
                    return ET.fromstring(elevation._build_elevation_task_xml(user_id))

            missing_task = compiled_task(missing_install)
            existing_task = compiled_task(existing_install)
            current_task = elevation._elevation_task_path(user_id)
            missing_task_path = r"\Ninja Capture Tool 1111111111111111"
            existing_task_path = r"\Ninja Capture Tool 2222222222222222"
            query = {
                missing_task_path: missing_task,
                existing_task_path: existing_task,
            }
            with (
                mock.patch.object(
                    elevation,
                    "_list_nct_elevation_tasks",
                    return_value=[current_task, missing_task_path, existing_task_path],
                ),
                mock.patch.object(elevation, "_query_elevation_task", side_effect=lambda path: query.get(path)),
                mock.patch.object(elevation, "_delete_elevation_task", return_value=True) as delete,
            ):
                self.assertEqual(elevation._cleanup_stale_elevation_tasks(user_id), 1)

            delete.assert_called_once_with(missing_task_path)

    def test_stale_task_cleanup_leaves_source_or_ambiguous_tasks_alone(self) -> None:
        user_id = "S-1-5-21-1-2-3-1001"
        with tempfile.TemporaryDirectory() as tmp:
            missing_install = Path(tmp) / "old-source-nct"
            with (
                mock.patch.object(elevation, "TOOL_DIR", missing_install),
                mock.patch.object(elevation.sys, "frozen", False, create=True),
                mock.patch.object(elevation.sys, "executable", "C:/Python/python.exe"),
            ):
                source_task = ET.fromstring(elevation._build_elevation_task_xml(user_id))
            task_path = r"\Ninja Capture Tool 3333333333333333"
            with (
                mock.patch.object(elevation, "_list_nct_elevation_tasks", return_value=[task_path]),
                mock.patch.object(elevation, "_query_elevation_task", return_value=source_task),
                mock.patch.object(elevation, "_delete_elevation_task") as delete,
            ):
                self.assertEqual(elevation._cleanup_stale_elevation_tasks(user_id), 0)
            delete.assert_not_called()

    def test_missing_installation_cleanup_requires_available_path_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing"
            self.assertTrue(elevation._installation_path_is_clearly_gone(missing))
        self.assertFalse(elevation._installation_path_is_clearly_gone(Path("relative-missing-install")))

    def test_elevation_handoff_state_uses_known_folder_local_app_data_and_isolated_installation_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            elevation, "nct_local_app_data_root", return_value=Path(tmp) / "DarkLotus" / "Ninja Capture Tool"
        ):
            with mock.patch.object(elevation, "TOOL_DIR", Path("C:/Ninja Capture Tool-A")):
                first = elevation._elevation_state_directory()
            with mock.patch.object(elevation, "TOOL_DIR", Path("D:/Ninja Capture Tool-B")):
                second = elevation._elevation_state_directory()

        local_root = Path(tmp) / "DarkLotus" / "Ninja Capture Tool" / "elevation"
        self.assertEqual(first.parent, local_root)
        self.assertEqual(second.parent, local_root)
        self.assertNotEqual(first, second)
        self.assertEqual(len(first.name), 16)
        self.assertEqual(len(second.name), 16)

    def test_remove_elevation_task_deletes_current_isolated_task(self) -> None:
        user_id = "S-1-5-21-1-2-3-1001"
        current = ET.fromstring(
            f"<Task><Principals><Principal><UserId>{user_id}</UserId></Principal></Principals></Task>"
        )
        task_path = elevation._elevation_task_path(user_id)

        def query(path):
            return current if path == task_path else None

        with (
            mock.patch.object(elevation.sys, "platform", "win32"),
            mock.patch.object(elevation, "_current_windows_user_id", return_value=user_id),
            mock.patch.object(elevation, "_query_elevation_task", side_effect=query),
            mock.patch.object(elevation, "_delete_elevation_task", return_value=True) as delete,
            mock.patch.object(elevation, "_cleanup_elevation_state_directory", return_value=True) as cleanup_state,
        ):
            self.assertTrue(elevation.remove_elevation_task())
        delete.assert_called_once_with(task_path)
        cleanup_state.assert_called_once_with()

    def test_elevation_handoff_cleanup_removes_schema_files_and_installation_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "installation"
            state.mkdir()
            for name in (
                ".elevation-request.json",
                ".elevation-ack-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json",
                ".elevation-request.lock",
                "..elevation-request.json.0123456789abcdef.tmp",
            ):
                (state / name).write_text("state", encoding="utf-8")
            with mock.patch.object(elevation, "_elevation_state_directory", return_value=state):
                self.assertTrue(elevation._cleanup_elevation_state_directory())
            self.assertFalse(state.exists())

    def test_elevation_handoff_uses_first_release_schema_and_derived_freshness_window(self) -> None:
        self.assertEqual(elevation.ELEVATION_HANDOFF_SCHEMA_VERSION, 1)
        self.assertEqual(
            elevation.ELEVATION_REQUEST_MAX_AGE_SECONDS,
            elevation.ELEVATION_HANDOFF_TIMEOUT_SECONDS + 5.0,
        )

    def test_new_elevation_request_cleanup_removes_orphaned_ack_and_temp_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "installation"
            state.mkdir()
            orphan_ack = state / f".elevation-ack-{'a' * 32}.json"
            orphan_temp = state / "..elevation-request.json.0123456789abcdef.tmp"
            request = state / ".elevation-request.json"
            lock = state / ".elevation-request.lock"
            for path in (orphan_ack, orphan_temp, request, lock):
                path.write_text("state", encoding="utf-8")
            with mock.patch.object(elevation, "_elevation_state_directory", return_value=state):
                elevation._cleanup_orphaned_elevation_handoff_artifacts()
            self.assertFalse(orphan_ack.exists())
            self.assertFalse(orphan_temp.exists())
            self.assertTrue(request.exists())
            self.assertTrue(lock.exists())

    def test_elevation_ack_requires_matching_schema_and_request_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ack = Path(tmp) / ".elevation-ack-test.json"
            expected = "e" * 32
            with mock.patch.object(elevation, "_elevation_ack_file", return_value=ack):
                ack.write_text(json.dumps({
                    "schema_version": elevation.ELEVATION_HANDOFF_SCHEMA_VERSION,
                    "request_id": "f" * 32,
                    "status": "started",
                }), encoding="utf-8")
                self.assertIsNone(elevation._matching_elevation_ack(expected))
                ack.write_text(json.dumps({
                    "schema_version": elevation.ELEVATION_HANDOFF_SCHEMA_VERSION + 1,
                    "request_id": expected,
                    "status": "started",
                }), encoding="utf-8")
                self.assertIsNone(elevation._matching_elevation_ack(expected))

    def test_elevation_request_rejects_expired_and_future_timestamps(self) -> None:
        base = {
            "schema_version": elevation.ELEVATION_HANDOFF_SCHEMA_VERSION,
            "request_id": "1" * 32,
            "argv": [],
            "task_installed": False,
        }
        with self.assertRaisesRegex(RuntimeError, "expired"):
            elevation._validate_elevation_request(
                dict(base, created_at_unix=100.0),
                now=100.0 + elevation.ELEVATION_REQUEST_MAX_AGE_SECONDS + 0.1,
            )
        with self.assertRaisesRegex(RuntimeError, "future"):
            elevation._validate_elevation_request(
                dict(base, created_at_unix=100.0 + elevation.ELEVATION_REQUEST_FUTURE_TOLERANCE_SECONDS + 0.1),
                now=100.0,
            )
        self.assertEqual(
            elevation._validate_elevation_request(dict(base, created_at_unix=100.0), now=100.0),
            ([], False, "1" * 32),
        )

    def test_delayed_old_ack_cannot_delete_newer_request(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            request = root / ".elevation-request.json"
            old_id = "2" * 32
            new_id = "3" * 32
            request.write_text(
                json.dumps({
                    "schema_version": elevation.ELEVATION_HANDOFF_SCHEMA_VERSION,
                    "request_id": new_id,
                    "created_at_unix": time.time(),
                    "argv": [],
                    "task_installed": False,
                }),
                encoding="utf-8",
            )
            with (
                mock.patch.object(elevation, "_elevation_request_file", return_value=request),
                mock.patch.object(
                    elevation,
                    "_elevation_ack_file",
                    side_effect=lambda request_id: root / f".elevation-ack-{request_id}.json",
                ),
            ):
                elevation.acknowledge_elevation_request(old_id)
                self.assertTrue(request.exists())
                self.assertFalse(elevation.clear_elevation_request(old_id))
                self.assertEqual(json.loads(request.read_text(encoding="utf-8"))["request_id"], new_id)
                self.assertEqual(elevation._matching_elevation_ack(old_id), ("started", None))
                self.assertIsNone(elevation._matching_elevation_ack(new_id))

    def test_failed_elevation_ack_surfaces_specific_startup_error(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "driver initialization failed"):
            elevation._raise_for_elevation_ack(("failed", "driver initialization failed"))

    def test_remove_elevation_task_does_not_delete_another_users_task(self) -> None:
        user_id = "S-1-5-21-1-2-3-1001"
        other = ET.fromstring(
            "<Task><Principals><Principal><UserId>S-1-5-21-1-2-3-2002</UserId></Principal></Principals></Task>"
        )
        with (
            mock.patch.object(elevation.sys, "platform", "win32"),
            mock.patch.object(elevation, "_current_windows_user_id", return_value=user_id),
            mock.patch.object(elevation, "_query_elevation_task", return_value=other),
            mock.patch.object(elevation, "_delete_elevation_task") as delete,
            mock.patch.object(elevation, "_cleanup_elevation_state_directory", return_value=True) as cleanup_state,
        ):
            self.assertFalse(elevation.remove_elevation_task())
        delete.assert_not_called()
        cleanup_state.assert_called_once_with()

    def test_remove_missing_elevation_task_is_a_noop(self) -> None:
        with (
            mock.patch.object(elevation.sys, "platform", "win32"),
            mock.patch.object(elevation, "_current_windows_user_id", return_value="S-1-5-21-1-2-3-1001"),
            mock.patch.object(elevation, "_query_elevation_task", return_value=None),
            mock.patch.object(elevation, "_delete_elevation_task") as delete,
            mock.patch.object(elevation, "_cleanup_elevation_state_directory", return_value=True) as cleanup_state,
        ):
            self.assertFalse(elevation.remove_elevation_task())
        delete.assert_not_called()
        cleanup_state.assert_called_once_with()

    def test_certificate_is_installed_permanently_for_local_machine_when_elevated(self) -> None:
        certificate = Path("C:/Users/Test/AppData/Local/DarkLotus/Ninja Capture Tool/mitmproxy/mitmproxy-ca-cert.cer")
        with (
            mock.patch.object(
                nct_runtime,
                "mitmproxy_ca_trust_status",
                side_effect=[("untrusted", certificate), ("trusted", certificate)],
            ),
            mock.patch.object(elevation, "is_elevated", return_value=True),
            mock.patch.object(nct_runtime, "add_certificate_to_local_machine_root") as install_certificate,
        ):
            self.assertTrue(nct_runtime.ensure_mitmproxy_ca_trusted())
        install_certificate.assert_called_once_with(certificate)

    def test_non_elevated_certificate_install_is_rejected_by_runtime_invariant(self) -> None:
        certificate = Path("C:/Users/Test/AppData/Local/DarkLotus/Ninja Capture Tool/mitmproxy/mitmproxy-ca-cert.cer")
        with (
            mock.patch.object(nct_runtime, "mitmproxy_ca_trust_status", return_value=("untrusted", certificate)),
            mock.patch.object(elevation, "is_elevated", return_value=False),
            mock.patch.object(nct_runtime, "add_certificate_to_local_machine_root") as install_certificate,
        ):
            with self.assertRaisesRegex(RuntimeError, "requires administrator privileges"):
                nct_runtime.ensure_mitmproxy_ca_trusted()
        install_certificate.assert_not_called()

    def test_elevated_helper_waits_for_process_without_startup_timeout(self) -> None:
        shell_execute = mock.MagicMock()
        def start_process(info_pointer):
            info_pointer._obj.hProcess = 123
            return 1
        shell_execute.side_effect = start_process

        wait = mock.MagicMock(return_value=0)
        def get_exit_code(handle, code_pointer):
            code_pointer._obj.value = 0
            return 1
        get_exit = mock.MagicMock(side_effect=get_exit_code)
        close = mock.MagicMock(return_value=1)
        shell32 = SimpleNamespace(ShellExecuteExW=shell_execute)
        kernel32 = SimpleNamespace(WaitForSingleObject=wait, GetExitCodeProcess=get_exit, CloseHandle=close)

        def fake_windll(name, **kwargs):
            return shell32 if name == "shell32" else kernel32

        with (
            mock.patch.object(nct.sys, "platform", "win32"),
            mock.patch.object(nct.ctypes, "WinDLL", side_effect=fake_windll, create=True),
        ):
            self.assertEqual(elevation.run_elevated_and_wait(["--example"]), 0)
        wait.assert_called_once_with(123, 0xFFFFFFFF)
        close.assert_called_once_with(123)

    def test_elevated_helper_can_show_maintenance_window(self) -> None:
        observed = {}
        shell_execute = mock.MagicMock()

        def start_process(info_pointer):
            observed["nShow"] = info_pointer._obj.nShow
            info_pointer._obj.hProcess = 123
            return 1

        shell_execute.side_effect = start_process
        shell32 = SimpleNamespace(ShellExecuteExW=shell_execute)

        def get_exit_code(_handle, code_pointer):
            code_pointer._obj.value = 0
            return 1

        kernel32 = SimpleNamespace(
            WaitForSingleObject=mock.MagicMock(return_value=0),
            GetExitCodeProcess=mock.MagicMock(side_effect=get_exit_code),
            CloseHandle=mock.MagicMock(return_value=1),
        )

        def fake_windll(name, **_kwargs):
            return shell32 if name == "shell32" else kernel32

        with (
            mock.patch.object(nct.sys, "platform", "win32"),
            mock.patch.object(nct.ctypes, "WinDLL", side_effect=fake_windll, create=True),
        ):
            self.assertEqual(elevation.run_elevated_and_wait(["--example"], show_window=True), 0)
        self.assertEqual(observed["nShow"], 1)

    def test_elevation_task_handoff_completes_only_with_matching_ack(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            request = Path(tmp) / ".elevation-request.json"
            ack = Path(tmp) / ".elevation-ack-test.json"
            request_id = "d" * 32
            sleeps = 0

            def wait_once(_seconds):
                nonlocal sleeps
                sleeps += 1
                ack.write_text(
                    json.dumps({
                        "schema_version": elevation.ELEVATION_HANDOFF_SCHEMA_VERSION,
                        "request_id": request_id,
                        "status": "started",
                    }),
                    encoding="utf-8",
                )

            with (
                mock.patch.object(elevation.sys, "platform", "win32"),
                mock.patch.object(elevation, "_prepare_elevation_state_directory"),
                mock.patch.object(elevation, "_elevation_request_file", return_value=request),
                mock.patch.object(elevation, "_elevation_ack_file", return_value=ack),
                mock.patch.object(elevation, "_elevation_request_lock_file", return_value=Path(tmp) / ".elevation-request.lock"),
                mock.patch.object(elevation, "windows_file_lock", return_value=contextlib.nullcontext()),
                mock.patch.object(instance_lock, "another_capture_is_active", return_value=False),
                mock.patch.object(elevation.uuid, "uuid4", return_value=SimpleNamespace(hex=request_id)),
                mock.patch.object(elevation, "_current_windows_user_id", return_value="S-1-5-21-1-2-3-1001"),
                mock.patch.object(elevation.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run,
                mock.patch.object(elevation.time, "sleep", side_effect=wait_once),
            ):
                elevation.launch_via_elevation_task([])
            self.assertEqual(sleeps, 1)
            run.assert_called_once()
            self.assertFalse(request.exists())
            self.assertFalse(ack.exists())

    def test_elevation_task_handoff_times_out_and_removes_stale_request(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            request = Path(tmp) / ".elevation-request.json"
            ack = Path(tmp) / ".elevation-ack-test.json"
            clock = [0.0]

            def monotonic():
                return clock[0]

            def sleep(seconds):
                clock[0] += max(seconds, 1.0)

            with (
                mock.patch.object(elevation.sys, "platform", "win32"),
                mock.patch.object(elevation, "_prepare_elevation_state_directory"),
                mock.patch.object(elevation, "_elevation_request_file", return_value=request),
                mock.patch.object(elevation, "_elevation_ack_file", return_value=ack),
                mock.patch.object(elevation, "_elevation_request_lock_file", return_value=Path(tmp) / ".elevation-request.lock"),
                mock.patch.object(elevation, "windows_file_lock", return_value=contextlib.nullcontext()),
                mock.patch.object(instance_lock, "another_capture_is_active", return_value=False),
                mock.patch.object(elevation, "_current_windows_user_id", return_value="S-1-5-21-1-2-3-1001"),
                mock.patch.object(elevation.subprocess, "run", return_value=SimpleNamespace(returncode=0)),
                mock.patch.object(elevation.time, "monotonic", side_effect=monotonic),
                mock.patch.object(elevation.time, "sleep", side_effect=sleep),
            ):
                with self.assertRaisesRegex(RuntimeError, "Timed out waiting|previous task instance"):
                    elevation.launch_via_elevation_task([])
            self.assertFalse(request.exists())
            self.assertFalse(ack.exists())

    def test_remove_https_certificate_reports_success_without_removing_elevation_task(self) -> None:
        stdout = io.StringIO()
        with (
            mock.patch.object(nct.sys, "platform", "win32"),
            mock.patch.object(nct, "handle_early_update_request", return_value=None),
            mock.patch.object(elevation, "is_elevated", return_value=True),
            mock.patch.object(nct_runtime, "remove_mitmproxy_ca", return_value=(1, True)) as remove_ca,
            mock.patch.object(elevation, "remove_elevation_task") as remove_task,
            mock.patch.object(nct_runtime, "show_console_window"),
            contextlib.redirect_stdout(stdout),
        ):
            self.assertEqual(nct.main(["--remove-https-certificate"]), 0)
        remove_ca.assert_called_once_with()
        remove_task.assert_not_called()
        self.assertEqual(stdout.getvalue(), "HTTPS certificate trust and shared CA files removed successfully.\n")

    def test_remove_https_certificate_uses_existing_elevation_task_without_uac(self) -> None:
        with (
            mock.patch.object(nct.sys, "platform", "win32"),
            mock.patch.object(nct, "handle_early_update_request", return_value=None),
            mock.patch.object(elevation, "is_elevated", return_value=False),
            mock.patch.object(nct, "another_capture_is_active", return_value=False),
            mock.patch.object(elevation, "elevation_task_is_current", return_value=True),
            mock.patch.object(elevation, "launch_via_elevation_task") as task_launch,
            mock.patch.object(nct_runtime, "show_console_window"),
        ):
            self.assertEqual(nct.main(["-C"]), 0)
        task_launch.assert_called_once_with(["--remove-https-certificate"])

    def test_remove_https_certificate_uses_synchronous_uac_when_no_current_elevation_task_exists(self) -> None:
        with (
            mock.patch.object(nct.sys, "platform", "win32"),
            mock.patch.object(nct, "handle_early_update_request", return_value=None),
            mock.patch.object(elevation, "is_elevated", return_value=False),
            mock.patch.object(nct, "another_capture_is_active", return_value=False),
            mock.patch.object(elevation, "elevation_task_is_current", return_value=False),
            mock.patch.object(elevation, "launch_via_elevation_task") as task_launch,
            mock.patch.object(elevation, "run_elevated_and_wait", return_value=0) as elevate,
            mock.patch.object(nct_runtime, "show_console_window"),
        ):
            self.assertEqual(nct.main(["-C"]), 0)
        task_launch.assert_not_called()
        elevate.assert_called_once_with(["--remove-https-certificate"], show_window=True)

    def test_remove_https_certificate_propagates_elevated_failure_exit_code(self) -> None:
        with (
            mock.patch.object(nct.sys, "platform", "win32"),
            mock.patch.object(nct, "handle_early_update_request", return_value=None),
            mock.patch.object(elevation, "is_elevated", return_value=False),
            mock.patch.object(nct, "another_capture_is_active", return_value=False),
            mock.patch.object(elevation, "elevation_task_is_current", return_value=False),
            mock.patch.object(elevation, "run_elevated_and_wait", return_value=7) as elevate,
            mock.patch.object(nct_runtime, "show_console_window"),
        ):
            self.assertEqual(nct.main(["-C"]), 7)
        elevate.assert_called_once_with(["--remove-https-certificate"], show_window=True)

    def test_remove_elevation_task_propagates_elevated_failure_exit_code(self) -> None:
        with (
            mock.patch.object(nct.sys, "platform", "win32"),
            mock.patch.object(nct, "handle_early_update_request", return_value=None),
            mock.patch.object(elevation, "elevation_task_exists", return_value=True),
            mock.patch.object(elevation, "is_elevated", return_value=False),
            mock.patch.object(elevation, "run_elevated_and_wait", return_value=9) as elevate,
            mock.patch.object(nct_runtime, "show_console_window"),
        ):
            self.assertEqual(nct.main(["-r"]), 9)
        elevate.assert_called_once_with(["--remove-elevation-task"], show_window=True)

    def test_remove_https_certificate_refuses_to_elevate_while_capture_is_active(self) -> None:
        stderr = io.StringIO()
        with (
            mock.patch.object(nct.sys, "platform", "win32"),
            mock.patch.object(nct, "handle_early_update_request", return_value=None),
            mock.patch.object(elevation, "is_elevated", return_value=False),
            mock.patch.object(nct, "another_capture_is_active", return_value=True),
            mock.patch.object(elevation, "launch_via_elevation_task") as task_launch,
            mock.patch.object(nct_runtime, "show_console_window"),
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(nct.main(["-C"]), 1)
        task_launch.assert_not_called()
        self.assertIn("while another capture is running", stderr.getvalue())

    def test_elevation_task_ca_removal_acknowledges_only_after_capture_lock(self) -> None:
        request_id = "a" * 32
        order: list[str] = []

        @contextlib.contextmanager
        def locked():
            order.append("lock")
            yield
            order.append("unlock")

        def acknowledge(*args, **kwargs):
            order.append("ack")

        def remove_ca():
            order.append("remove")
            return 1, True

        with (
            mock.patch.object(nct.sys, "platform", "win32"),
            mock.patch.object(elevation, "current_elevation_request_id", return_value=request_id),
            mock.patch.object(elevation, "consume_elevation_request", return_value=(["--remove-https-certificate"], False, request_id)),
            mock.patch.object(elevation, "is_elevated", return_value=True),
            mock.patch.object(nct, "handle_early_update_request", return_value=None),
            mock.patch.object(nct, "capture_lock", side_effect=locked),
            mock.patch.object(elevation, "acknowledge_elevation_request", side_effect=acknowledge) as ack,
            mock.patch.object(nct_runtime, "remove_mitmproxy_ca", side_effect=remove_ca),
            mock.patch.object(nct_runtime, "show_console_window"),
        ):
            self.assertEqual(nct.main([elevation.ELEVATION_TASK_RUN_ARGUMENT]), 0)
        self.assertEqual(order, ["lock", "remove", "ack", "unlock"])
        ack.assert_called_once_with(request_id)

    def test_remove_https_certificate_must_be_standalone(self) -> None:
        stderr = io.StringIO()
        with (
            mock.patch.object(nct.sys, "platform", "win32"),
            mock.patch.object(nct_runtime, "show_console_window") as show_console,
            contextlib.redirect_stderr(stderr),
        ):
            with self.assertRaises(SystemExit):
                nct.main(["-C", "-m", "local"])
        show_console.assert_called_once_with()
        self.assertIn("--remove-https-certificate must be used without other arguments", stderr.getvalue())
