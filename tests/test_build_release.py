# Run from the project root with: py -B -m unittest discover -s tests
from support import *

class BuildReleaseTests(NctTestBase):
    def test_local_capture_runtime_is_staged_outside_release_and_old_unlocked_runtime_is_removed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "release-runtime"
            source.mkdir()
            payloads = {
                "windows-redirector.exe": b"redirector-v1",
                "WinDivert.dll": b"dll-v1",
                "WinDivert64.sys": b"driver-v1",
                "WinDivert.lib": b"import-lib-v1",
            }
            for name, payload in payloads.items():
                (source / name).write_bytes(payload)
            runtime_root = root / "localappdata-runtime"
            old_runtime = runtime_root / "old-runtime"
            old_runtime.mkdir(parents=True)
            (old_runtime / "old.bin").write_bytes(b"old")
            module = ModuleType("mitmproxy_windows")
            module.executable_path = lambda: source / "windows-redirector.exe"
            with (
                mock.patch.object(nct.sys, "platform", "win32"),
                mock.patch.dict(sys.modules, {"mitmproxy_windows": module}),
                mock.patch.object(nct, "_local_capture_runtime_root", return_value=runtime_root),
                mock.patch.object(nct, "_windivert_driver_loaded", return_value=False),
            ):
                staged_executable = nct.prepare_windows_local_capture_runtime()

            self.assertIsNotNone(staged_executable)
            assert staged_executable is not None
            self.assertNotEqual(staged_executable.parent, source)
            self.assertEqual(staged_executable.parent.parent, runtime_root)
            self.assertRegex(staged_executable.parent.name, rf"^{re.escape(common.MITMPROXY_VERSION)}-[0-9a-f]{{64}}$")
            self.assertEqual(module.executable_path(), staged_executable)
            for name in ("windows-redirector.exe", "WinDivert.dll", "WinDivert64.sys"):
                self.assertEqual((staged_executable.parent / name).read_bytes(), payloads[name])
            self.assertFalse((staged_executable.parent / "WinDivert.lib").exists())
            self.assertFalse(old_runtime.exists())

    def test_release_source_files_cover_all_python_source_and_tests(self) -> None:
        root = Path(build_release.__file__).resolve().parent
        expected = {path.name for path in root.glob("*.py") if path.is_file()}
        expected.update(
            path.relative_to(root).as_posix()
            for path in (root / "tests").glob("*.py")
            if path.is_file()
        )
        declared = set(build_release.RELEASE_SOURCE_FILES)
        missing = sorted(expected - declared, key=str.casefold)
        self.assertEqual(missing, [], "Python release inputs missing from RELEASE_SOURCE_FILES:\n" + "\n".join(missing))

    def test_source_tree_cleanliness_detects_generated_artifacts_and_runtime_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".pytest_cache").mkdir()
            (root / ".mypy_cache").mkdir()
            (root / ".ruff_cache").mkdir()
            (root / "htmlcov").mkdir()
            (root / ".coverage").write_text("coverage", encoding="ascii")
            (root / "coverage.xml").write_text("coverage", encoding="ascii")
            (root / ".git").mkdir()
            (root / ".git" / "index.lock").write_text("git index lock", encoding="ascii")
            (root / "nested").mkdir()
            (root / "nested" / "download.tmp.part").write_bytes(b"partial")
            (root / "nested" / "__pycache__").mkdir()
            (root / "nested" / "module.pyc").write_bytes(b"bytecode")
            (root / "nested" / "module.pyo").write_bytes(b"optimized bytecode")
            (root / "data").mkdir()
            (root / "data" / ".capture.lock").write_text("1", encoding="ascii")

            self.assertEqual(
                build_release.source_tree_artifacts(root),
                [
                    ".coverage",
                    ".mypy_cache/",
                    ".pytest_cache/",
                    ".ruff_cache/",
                    "coverage.xml",
                    "data/.capture.lock",
                    "htmlcov/",
                    "nested/__pycache__/",
                    "nested/download.tmp.part",
                    "nested/module.pyc",
                    "nested/module.pyo",
                ],
            )
            with self.assertRaisesRegex(RuntimeError, "Generated/cache artifacts must be removed"):
                build_release.validate_source_tree_cleanliness(root)

    def test_release_cleanliness_allows_known_runtime_locks_and_rejects_unknown_locks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = root / "data"
            data.mkdir()
            for relative in build_release.KNOWN_RUNTIME_LOCK_FILES:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("lock", encoding="utf-8")
            (data / ".runtime.lock").write_text("lock", encoding="utf-8")
            self.assertEqual(build_release.source_tree_artifacts(root), ["data/.runtime.lock"])
            with self.assertRaisesRegex(RuntimeError, "Generated/cache artifacts"):
                build_release.validate_source_tree_cleanliness(root)

    def test_release_runtime_build_barrier_holds_update_and_localappdata_capture_locks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture_lock = root / "external.capture.lock"
            events: list[tuple[str, str]] = []

            @contextlib.contextmanager
            def fake_lock(path: Path, timeout_seconds: int, timeout_message: str):
                self.assertEqual(timeout_seconds, 0)
                label = path.relative_to(root).as_posix()
                events.append((f"enter:{label}", timeout_message))
                try:
                    yield
                finally:
                    events.append((f"exit:{label}", timeout_message))

            with (
                mock.patch.object(build_release.sys, "platform", "win32"),
                mock.patch.object(build_release, "capture_activity_lock_path", return_value=capture_lock),
                mock.patch.object(build_release, "windows_file_lock", side_effect=fake_lock),
            ):
                with build_release.runtime_build_barrier(root):
                    events.append(("build", ""))

            self.assertEqual(
                events,
                [
                    ("enter:data/.update.lock", "Active runtime lock: data/.update.lock"),
                    ("enter:external.capture.lock", "Active runtime lock: LocalAppData capture lock"),
                    ("build", ""),
                    ("exit:external.capture.lock", "Active runtime lock: LocalAppData capture lock"),
                    ("exit:data/.update.lock", "Active runtime lock: data/.update.lock"),
                ],
            )

    def test_release_runtime_build_barrier_releases_update_lock_when_capture_lock_is_busy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture_lock = root / "external.capture.lock"
            events: list[str] = []

            @contextlib.contextmanager
            def fake_lock(path: Path, _timeout_seconds: int, timeout_message: str):
                relative = path.relative_to(root).as_posix()
                if path == capture_lock:
                    raise build_release.FileLockBusyError(timeout_message)
                events.append(f"enter:{relative}")
                try:
                    yield
                finally:
                    events.append(f"exit:{relative}")

            with (
                mock.patch.object(build_release.sys, "platform", "win32"),
                mock.patch.object(build_release, "capture_activity_lock_path", return_value=capture_lock),
                mock.patch.object(build_release, "windows_file_lock", side_effect=fake_lock),
            ):
                with self.assertRaisesRegex(RuntimeError, "Close it before building a release"):
                    with build_release.runtime_build_barrier(root):
                        self.fail("busy runtime barrier unexpectedly entered")

            self.assertEqual(events, ["enter:data/.update.lock", "exit:data/.update.lock"])

    def test_release_runtime_build_barrier_does_not_relabel_body_permission_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            @contextlib.contextmanager
            def fake_lock(_path: Path, _timeout_seconds: int, _timeout_message: str):
                yield

            with (
                mock.patch.object(build_release.sys, "platform", "win32"),
                mock.patch.object(build_release, "capture_activity_lock_path", return_value=root / "external.capture.lock"),
                mock.patch.object(build_release, "windows_file_lock", side_effect=fake_lock),
            ):
                with self.assertRaisesRegex(PermissionError, "packaged release cleanup is locked"):
                    with build_release.runtime_build_barrier(root):
                        raise PermissionError("packaged release cleanup is locked")

    def test_release_runtime_build_barrier_reports_permission_error_during_lock_acquisition(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            @contextlib.contextmanager
            def denied_lock(_path: Path, _timeout_seconds: int, _timeout_message: str):
                raise PermissionError("denied")
                yield

            with (
                mock.patch.object(build_release.sys, "platform", "win32"),
                mock.patch.object(build_release, "capture_activity_lock_path", return_value=root / "external.capture.lock"),
                mock.patch.object(build_release, "windows_file_lock", side_effect=denied_lock),
            ):
                with self.assertRaisesRegex(RuntimeError, "runtime locks could not be acquired"):
                    with build_release.runtime_build_barrier(root):
                        self.fail("permission-denied runtime barrier unexpectedly entered")

    def test_release_staging_removes_known_locks_and_rejects_unknown_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            stage = Path(tmp)
            for relative in build_release.KNOWN_RUNTIME_LOCK_FILES:
                path = stage / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("lock", encoding="ascii")
            unexpected = stage / "data" / ".unexpected.lock"
            unexpected.write_text("lock", encoding="ascii")

            with self.assertRaisesRegex(RuntimeError, "unexpected runtime lock files"):
                build_release.sanitize_staged_runtime_locks(stage)
            self.assertTrue(unexpected.exists())
            self.assertTrue(all(not (stage / relative).exists() for relative in build_release.KNOWN_RUNTIME_LOCK_FILES))

            unexpected.unlink()
            build_release.sanitize_staged_runtime_locks(stage)

    def test_release_main_revalidates_cleanliness_after_source_tests(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            release_temp = Path(tmp) / "release_temp"
            events: list[str] = []

            def run_tests() -> None:
                events.append("tests")

            def validate_cleanliness() -> None:
                events.append("cleanliness")

            fingerprints = iter(("same", "same"))

            def source_fingerprint() -> str:
                events.append("fingerprint")
                return next(fingerprints)

            @contextlib.contextmanager
            def runtime_barrier():
                events.append("barrier-enter")
                try:
                    yield
                finally:
                    events.append("barrier-exit")

            with (
                mock.patch.object(build_release, "RELEASE_TEMP_DIR", release_temp),
                mock.patch.object(build_release, "RELEASE_DIR", Path(tmp) / "release"),
                mock.patch.object(build_release, "validate_environment"),
                mock.patch.object(build_release, "release_lock", return_value=contextlib.nullcontext()),
                mock.patch.object(build_release, "release_console_cleanup", return_value=contextlib.nullcontext()),
                mock.patch.object(build_release, "clean_stale_release_temp"),
                mock.patch.object(build_release, "runtime_build_barrier", side_effect=runtime_barrier),
                mock.patch.object(build_release, "release_source_fingerprint", side_effect=source_fingerprint),
                mock.patch.object(build_release, "run_tests", side_effect=run_tests),
                mock.patch.object(build_release, "validate_source_tree_cleanliness", side_effect=validate_cleanliness),
                mock.patch.object(build_release, "create_version_file", return_value=Path("version.txt")),
                mock.patch.object(build_release, "create_application_manifest", return_value=Path("app.manifest")),
                mock.patch.object(build_release, "build_executable", side_effect=RuntimeError("stop after cleanliness")),
                mock.patch.object(build_release, "remove_release_temp"),
                mock.patch("sys.stderr", io.StringIO()),
            ):
                self.assertEqual(build_release.main([]), 1)
            self.assertEqual(
                events,
                [
                    "barrier-enter",
                    "fingerprint",
                    "barrier-exit",
                    "tests",
                    "barrier-enter",
                    "cleanliness",
                    "fingerprint",
                    "barrier-exit",
                ],
            )

    def test_release_main_rejects_source_change_during_source_tests(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            release_temp = Path(tmp) / "release_temp"
            build_executable = mock.Mock(side_effect=AssertionError("build must not start"))
            stderr = io.StringIO()
            with (
                mock.patch.object(build_release, "RELEASE_TEMP_DIR", release_temp),
                mock.patch.object(build_release, "RELEASE_DIR", Path(tmp) / "release"),
                mock.patch.object(build_release, "validate_environment"),
                mock.patch.object(build_release, "release_lock", return_value=contextlib.nullcontext()),
                mock.patch.object(build_release, "release_console_cleanup", return_value=contextlib.nullcontext()),
                mock.patch.object(build_release, "clean_stale_release_temp"),
                mock.patch.object(build_release, "runtime_build_barrier", return_value=contextlib.nullcontext()),
                mock.patch.object(build_release, "release_source_fingerprint", side_effect=["before", "after"]),
                mock.patch.object(build_release, "run_tests"),
                mock.patch.object(build_release, "validate_source_tree_cleanliness"),
                mock.patch.object(build_release, "build_executable", build_executable),
                contextlib.redirect_stderr(stderr),
            ):
                self.assertEqual(build_release.main([]), 1)
            build_executable.assert_not_called()
            self.assertIn("Release source changed while the source test suite was running", stderr.getvalue())

    def test_release_outputs_are_built_in_private_publication_and_classify_previous_archive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage = self.make_release_stage(root)
            temporary = root / "release_temp"
            previous = temporary / "previous_release"
            first_publication = temporary / "first_publication"
            temporary.mkdir()
            with (
                mock.patch.object(build_release, "RELEASE_TEMP_DIR", temporary),
                mock.patch.object(build_release, "smoke_test_release_archive"),
            ):
                archive, checksum, digest, result = build_release.create_release_outputs(stage, first_publication)
                self.assertEqual(result, "created")
                self.assertEqual(archive.parent, first_publication)
                self.assertEqual(checksum.parent, first_publication)
                self.assertEqual(checksum.read_text(encoding="ascii"), f"{digest}  {archive.name}\n")

                build_release.shutil.copytree(first_publication, previous)
                build_release.shutil.rmtree(first_publication)
                same_publication = temporary / "same_publication"
                _, _, same_digest, result = build_release.create_release_outputs(stage, same_publication, previous)
                self.assertEqual(result, "unchanged")
                self.assertEqual(same_digest, digest)

                build_release.shutil.rmtree(same_publication)
                (stage / "NinjaCaptureTool.exe").write_bytes(b"changed-exe")
                build_release.write_release_manifest(stage)
                changed_publication = temporary / "changed_publication"
                _, _, changed_digest, result = build_release.create_release_outputs(stage, changed_publication, previous)
                self.assertEqual(result, "replaced")
                self.assertNotEqual(changed_digest, digest)

    def test_release_output_failure_removes_private_publication_and_preserves_previous_release(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage = self.make_release_stage(root)
            temporary = root / "release_temp"
            previous = temporary / "previous_release"
            publication = temporary / "publication"
            previous.mkdir(parents=True)
            marker = previous / "keep.txt"
            marker.write_text("old release", encoding="ascii")
            with (
                mock.patch.object(build_release, "RELEASE_TEMP_DIR", temporary),
                mock.patch.object(build_release, "validate_release_archive", side_effect=RuntimeError("validation failed")),
                mock.patch.object(build_release, "smoke_test_release_archive"),
            ):
                with self.assertRaisesRegex(RuntimeError, "validation failed"):
                    build_release.create_release_outputs(stage, publication, previous)
            self.assertFalse(publication.exists())
            self.assertEqual(marker.read_text(encoding="ascii"), "old release")

    def test_existing_release_is_hidden_in_release_temp_and_can_be_restored(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            release_dir = root / "release"
            temporary = root / "release_temp"
            release_dir.mkdir()
            (release_dir / "old.txt").write_text("old", encoding="ascii")
            temporary.mkdir()
            with (
                mock.patch.object(build_release, "RELEASE_DIR", release_dir),
                mock.patch.object(build_release, "RELEASE_TEMP_DIR", temporary),
            ):
                self.assertTrue(build_release.stash_existing_release())
                self.assertFalse(release_dir.exists())
                self.assertEqual((build_release.previous_release_path() / "old.txt").read_text(encoding="ascii"), "old")
                build_release._restore_stashed_release_if_needed()
            self.assertTrue(release_dir.is_dir())
            self.assertEqual((release_dir / "old.txt").read_text(encoding="ascii"), "old")
            self.assertFalse((temporary / "previous_release").exists())

    def test_final_publication_appears_only_when_directory_is_published(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            release_dir = root / "release"
            temporary = root / "release_temp"
            publication = temporary / "publication"
            publication.mkdir(parents=True)
            (publication / "archive.zip").write_bytes(b"zip")
            with (
                mock.patch.object(build_release, "RELEASE_DIR", release_dir),
                mock.patch.object(build_release, "RELEASE_TEMP_DIR", temporary),
            ):
                self.assertFalse(release_dir.exists())
                build_release.publish_release_directory(publication)
            self.assertTrue(release_dir.is_dir())
            self.assertEqual((release_dir / "archive.zip").read_bytes(), b"zip")
            self.assertFalse(publication.exists())

    def test_release_publication_rejects_any_nonfinal_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            publication = Path(tmp) / "publication"
            publication.mkdir()
            archive = build_release.release_archive_path(publication)
            checksum = build_release.release_checksum_path(publication)
            archive.write_bytes(b"zip")
            checksum.write_text("checksum", encoding="ascii")
            (publication / "unexpected.tmp").write_text("temp", encoding="ascii")
            with self.assertRaisesRegex(RuntimeError, "Unexpected final release publication contents"):
                build_release.validate_release_publication(publication, include_extracted=False)

    def test_release_output_keyboard_interrupt_removes_private_publication(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage = self.make_release_stage(root)
            publication = root / "release_temp" / "publication"
            with (
                mock.patch.object(build_release, "validate_release_archive", side_effect=KeyboardInterrupt),
                mock.patch.object(build_release, "smoke_test_release_archive"),
            ):
                with self.assertRaises(KeyboardInterrupt):
                    build_release.create_release_outputs(stage, publication)
            self.assertFalse(publication.exists())

    def test_release_builder_console_title_includes_version_and_restores_previous_title(self) -> None:
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
                self.GetConsoleTitleW = Function(self.get_console_title)
                self.SetConsoleTitleW = Function(self.set_console_title)

            @staticmethod
            def get_console_title(buffer, size):
                buffer.value = "Original Build Title"
                return len(buffer.value)

            @staticmethod
            def set_console_title(title):
                calls.append(title)
                return 1

        with (
            mock.patch.object(build_release.sys, "platform", "win32"),
            mock.patch.object(build_release.ctypes, "WinDLL", return_value=Kernel32(), create=True),
            mock.patch.object(build_release, "main", return_value=0) as main,
        ):
            self.assertEqual(build_release.run_main_with_console_title(["--extract"]), 0)
        main.assert_called_once_with(["--extract"])
        self.assertEqual(calls[0], f"Building latest release... - Ninja Capture Tool (v{common.display_version()})")
        self.assertEqual(calls[-1], "Original Build Title")

    def test_release_console_close_event_restores_previous_release_before_temp_cleanup(self) -> None:
        events: list[str] = []
        with (
            mock.patch.object(build_release, "_terminate_active_build_process", side_effect=lambda: events.append("terminate")),
            mock.patch.object(build_release, "_restore_stashed_release_if_needed", side_effect=lambda: events.append("restore")),
            mock.patch.object(build_release, "remove_release_temp", side_effect=lambda: events.append("cleanup")),
        ):
            self.assertFalse(build_release._release_console_control_handler(2))
            self.assertFalse(build_release._release_console_control_handler(0))
        self.assertEqual(events, ["terminate", "restore", "cleanup"])

    def test_release_main_publishes_only_final_outputs_and_removes_release_temp(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            temporary = root / "release_temp"
            release_dir = root / "release"

            def fake_build(
                dist: Path, work: Path, specs: Path, version_file: Path, manifest_file: Path
            ) -> Path:
                distribution = dist / "NinjaCaptureTool"
                runtime = distribution / common.FROZEN_RUNTIME_DIR_NAME
                runtime.mkdir(parents=True)
                (runtime / "python314.dll").write_bytes(b"runtime")
                executable = distribution / "NinjaCaptureTool.exe"
                executable.write_bytes(b"exe")
                return executable

            def fake_licenses(stage: Path) -> None:
                licenses = stage / "data" / "licenses"
                licenses.mkdir(parents=True, exist_ok=True)
                (licenses / "dependency-LICENSE.txt").write_text("license", encoding="utf-8")

            def fake_release_outputs(stage: Path, publication: Path, previous: Path | None):
                self.assertFalse(release_dir.exists())
                self.assertIsNone(previous)
                publication.mkdir()
                archive = build_release.release_archive_path(publication)
                checksum = build_release.release_checksum_path(publication)
                archive.write_bytes(b"zip")
                checksum.write_text("checksum", encoding="ascii")
                return archive, checksum, "a" * 64, "created"

            with (
                mock.patch.object(build_release, "RELEASE_TEMP_DIR", temporary),
                mock.patch.object(build_release, "RELEASE_DIR", release_dir),
                mock.patch.object(build_release, "validate_environment"),
                mock.patch.object(build_release, "release_lock", return_value=contextlib.nullcontext()),
                mock.patch.object(build_release, "run_tests"),
                mock.patch.object(build_release, "validate_source_tree_cleanliness"),
                mock.patch.object(build_release, "build_executable", side_effect=fake_build),
                mock.patch.object(build_release, "smoke_test"),
                mock.patch.object(build_release, "smoke_test_frozen_capture"),
                mock.patch.object(build_release, "collect_third_party_licenses", side_effect=fake_licenses),
                mock.patch.object(build_release, "create_release_outputs", side_effect=fake_release_outputs),
            ):
                self.assertEqual(build_release.main(), 0)

            self.assertFalse(temporary.exists())
            self.assertEqual(
                {path.name for path in release_dir.iterdir()},
                {
                    f"NinjaCaptureTool-v{common.VERSION}-Windows-x64.zip",
                    f"NinjaCaptureTool-v{common.VERSION}-Windows-x64.zip.sha256",
                },
            )

    def test_release_main_restores_previous_release_when_build_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            temporary = root / "release_temp"
            release_dir = root / "release"
            release_dir.mkdir()
            marker = release_dir / "previous.txt"
            marker.write_text("keep", encoding="ascii")
            stderr = io.StringIO()

            def fail_tests() -> None:
                self.assertFalse(release_dir.exists())
                self.assertEqual(
                    (temporary / "previous_release" / "previous.txt").read_text(encoding="ascii"),
                    "keep",
                )
                raise RuntimeError("build failed")

            with (
                mock.patch.object(build_release, "RELEASE_TEMP_DIR", temporary),
                mock.patch.object(build_release, "RELEASE_DIR", release_dir),
                mock.patch.object(build_release, "validate_environment"),
                mock.patch.object(build_release, "release_lock", return_value=contextlib.nullcontext()),
                mock.patch.object(build_release, "run_tests", side_effect=fail_tests),
                contextlib.redirect_stderr(stderr),
            ):
                self.assertEqual(build_release.main(), 1)
            self.assertIn("build failed", stderr.getvalue())
            self.assertTrue(release_dir.is_dir())
            self.assertEqual((release_dir / "previous.txt").read_text(encoding="ascii"), "keep")
            self.assertFalse(temporary.exists())

    def test_remove_path_with_retry_recovers_from_transient_windows_lock(self) -> None:
        path = Path("locked")
        remove = mock.Mock(side_effect=[PermissionError("busy"), PermissionError("busy"), None])
        with (
            mock.patch.object(build_release, "_remove_path", remove),
            mock.patch.object(build_release.time, "sleep") as sleep,
        ):
            build_release._remove_path_with_retry(path, attempts=3, delay_seconds=0.01)
        self.assertEqual(remove.call_count, 3)
        self.assertEqual(sleep.call_count, 2)

    def test_replace_path_with_retry_recovers_from_transient_windows_lock(self) -> None:
        source = mock.Mock()
        source.replace.side_effect = [PermissionError("busy"), None]
        destination = Path("destination")
        with mock.patch.object(build_release.time, "sleep") as sleep:
            build_release._replace_path_with_retry(source, destination, attempts=2, delay_seconds=0.01)
        self.assertEqual(source.replace.call_count, 2)
        sleep.assert_called_once_with(0.01)

    def test_stale_release_temp_restores_previous_release_before_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            temporary = root / "release_temp"
            release_dir = root / "release"
            previous = temporary / "previous_release"
            previous.mkdir(parents=True)
            (previous / "old.txt").write_text("old", encoding="ascii")
            (temporary / "partial.tmp").write_text("partial", encoding="ascii")
            with (
                mock.patch.object(build_release, "RELEASE_TEMP_DIR", temporary),
                mock.patch.object(build_release, "RELEASE_DIR", release_dir),
            ):
                build_release.clean_stale_release_temp()
            self.assertTrue(release_dir.is_dir())
            self.assertEqual((release_dir / "old.txt").read_text(encoding="ascii"), "old")
            self.assertFalse(temporary.exists())

    def test_packaged_release_smoke_test_uses_extracted_onedir_copy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "release.zip"
            prefix = f"NinjaCaptureTool-v{common.VERSION}"
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr(f"{prefix}/NinjaCaptureTool.exe", b"exe")
                output.writestr(f"{prefix}/{common.FROZEN_RUNTIME_DIR_NAME}/python314.dll", b"runtime")
            seen: list[Path] = []

            def remember(executable: Path) -> None:
                seen.append(executable)

            with (
                mock.patch.object(build_release, "RELEASE_TEMP_DIR", root / "release_temp"),
                mock.patch.object(build_release, "smoke_test", side_effect=remember),
                mock.patch.object(build_release, "smoke_test_frozen_capture", side_effect=remember),
            ):
                build_release.smoke_test_release_archive(archive)

            self.assertEqual(len(seen), 2)
            self.assertTrue(all(path.name == "NinjaCaptureTool.exe" for path in seen))
            self.assertTrue(all("archive_smoke" in path.parts for path in seen))
            self.assertFalse((root / "release_temp" / "archive_smoke").exists())

    def test_release_main_smoke_tests_disposable_onedir_copy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            temporary = root / "release_temp"
            release_dir = root / "release"
            smoke_paths: list[Path] = []

            def fake_build(
                dist: Path, work: Path, specs: Path, version_file: Path, manifest_file: Path
            ) -> Path:
                distribution = dist / "NinjaCaptureTool"
                runtime = distribution / common.FROZEN_RUNTIME_DIR_NAME
                runtime.mkdir(parents=True)
                (runtime / "python314.dll").write_bytes(b"runtime")
                executable = distribution / "NinjaCaptureTool.exe"
                executable.write_bytes(b"exe")
                return executable

            def mutating_smoke(executable: Path) -> None:
                smoke_paths.append(executable)
                (executable.parent / "smoke-side-effect.tmp").write_text("generated", encoding="ascii")

            def fake_licenses(stage: Path) -> None:
                licenses = stage / "data" / "licenses"
                licenses.mkdir(parents=True, exist_ok=True)
                (licenses / "dependency-LICENSE.txt").write_text("license", encoding="utf-8")

            def fake_release_outputs(stage: Path, publication: Path, previous: Path | None):
                self.assertFalse((stage / "smoke-side-effect.tmp").exists())
                self.assertIsNone(previous)
                publication.mkdir()
                archive = build_release.release_archive_path(publication)
                checksum = build_release.release_checksum_path(publication)
                archive.write_bytes(b"zip")
                checksum.write_text("checksum", encoding="ascii")
                return archive, checksum, "a" * 64, "created"

            with (
                mock.patch.object(build_release, "RELEASE_TEMP_DIR", temporary),
                mock.patch.object(build_release, "RELEASE_DIR", release_dir),
                mock.patch.object(build_release, "validate_environment"),
                mock.patch.object(build_release, "release_lock", return_value=contextlib.nullcontext()),
                mock.patch.object(build_release, "run_tests"),
                mock.patch.object(build_release, "validate_source_tree_cleanliness"),
                mock.patch.object(build_release, "build_executable", side_effect=fake_build),
                mock.patch.object(build_release, "smoke_test", side_effect=mutating_smoke),
                mock.patch.object(build_release, "smoke_test_frozen_capture", side_effect=mutating_smoke),
                mock.patch.object(build_release, "collect_third_party_licenses", side_effect=fake_licenses),
                mock.patch.object(build_release, "create_release_outputs", side_effect=fake_release_outputs),
            ):
                self.assertEqual(build_release.main(), 0)

            self.assertEqual(len(smoke_paths), 2)
            self.assertTrue(all(path.parent.name == "NinjaCaptureTool" for path in smoke_paths))
            self.assertTrue(all("smoke" in path.parts for path in smoke_paths))
            self.assertFalse(temporary.exists())

    def test_release_main_reports_keyboard_interrupt_without_traceback(self) -> None:
        stderr = io.StringIO()
        with (
            mock.patch.object(build_release, "validate_environment", side_effect=KeyboardInterrupt),
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(build_release.main(), 130)
        self.assertIn("Release creation interrupted.", stderr.getvalue())

    def test_release_builder_extract_argument_aliases(self) -> None:
        self.assertTrue(build_release.parse_args(["-e"]).extract)
        self.assertTrue(build_release.parse_args(["--extract"]).extract)
        self.assertFalse(build_release.parse_args([]).extract)

    def test_release_builder_argument_errors_use_styled_error_prefix(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as raised:
                build_release.parse_args(["-x"])
        self.assertEqual(raised.exception.code, 2)
        output = stderr.getvalue()
        self.assertIn("usage:", output)
        self.assertIn("ERROR: Unrecognized arguments: -x", output)
        self.assertNotIn("build_release.py: error:", output)

    def test_release_archive_extraction_stays_inside_private_publication(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage = self.make_release_stage(root)
            publication = root / "release_temp" / "publication"
            with mock.patch.object(build_release, "smoke_test_release_archive"):
                archive, _, _, _ = build_release.create_release_outputs(stage, publication)
            extracted = build_release.extract_release_archive(archive, publication)
            self.assertEqual(extracted, build_release.release_extract_path(publication))
            self.assertTrue((extracted / "NinjaCaptureTool.exe").is_file())
            build_release.validate_release_publication(publication, include_extracted=True)

    def test_pyinstaller_build_embeds_icon_mitmproxy_and_windows_redirector_package(self) -> None:
        command = build_release.pyinstaller_command(Path("dist"), Path("work"), Path("specs"), Path("version.txt"), Path("app.manifest"))
        self.assertIn("--onedir", command)
        self.assertNotIn("--onefile", command)
        self.assertIn("--windowed", command)
        self.assertNotIn("--console", command)
        self.assertNotIn("--hide-console", command)
        pairs = list(zip(command, command[1:]))
        self.assertIn(("--contents-directory", common.FROZEN_RUNTIME_DIR_NAME), pairs)
        self.assertIn(("--icon", str(build_release.FAVICON)), pairs)
        self.assertIn(("--collect-all", "mitmproxy"), pairs)
        self.assertIn(("--collect-all", "mitmproxy_rs"), pairs)
        self.assertIn(("--collect-all", "mitmproxy_windows"), pairs)
        self.assertIn(("--recursive-copy-metadata", "mitmproxy"), pairs)
        self.assertIn(("--collect-all", "steam"), pairs)
        self.assertIn(("--recursive-copy-metadata", "pysteam-client"), pairs)
        self.assertIn(("--log-level", "WARN"), pairs)
        self.assertIn(("--manifest", "app.manifest"), pairs)
        self.assertIn(("--exclude-module", "pycparser.lextab"), pairs)
        self.assertIn(("--exclude-module", "pycparser.yacctab"), pairs)
        self.assertNotIn("--uac-admin", command)
        self.assertNotIn("--uac-uiaccess", command)

    def test_release_preflight_validates_ico_structure(self) -> None:
        build_release.validate_ico(build_release.FAVICON)
        with tempfile.TemporaryDirectory() as tmp:
            icon = Path(tmp) / "bad.ico"
            icon.write_bytes(b"not an icon")
            with self.assertRaisesRegex(RuntimeError, "Invalid ICO"):
                build_release.validate_ico(icon)

            old_style = Path(tmp) / "old-style.ico"
            payload = b"not-png"
            old_style.write_bytes(
                b"\x00\x00\x01\x00\x01\x00"
                + b"\x00\x00\x00\x00\x01\x00\x20\x00"
                + len(payload).to_bytes(4, "little")
                + (22).to_bytes(4, "little")
                + payload
            )
            with self.assertRaisesRegex(RuntimeError, "exactly these resolutions"):
                build_release.validate_ico(old_style)

    def test_release_build_environment_disables_nct_elevation_paths(self) -> None:
        environment = build_release.release_build_environment()
        self.assertEqual(environment[common.RELEASE_BUILD_ENV], "1")
        with mock.patch.dict(os.environ, {common.RELEASE_BUILD_ENV: "1"}, clear=False):
            with self.assertRaisesRegex(RuntimeError, "Elevation is disabled"):
                elevation.run_elevated_and_wait([])

    def test_release_executable_smoke_checks_are_headless(self) -> None:
        normal_output = f"Ninja Capture Tool v{common.display_version()}\nCapture Warframe CDN responses\n"
        smoke_output = steam_tracking.STEAM_QUERY_RESULT_PREFIX + json.dumps({"ok": True, "smoke": "steam-import"}) + "\n"

        def run(command, **kwargs):
            output = smoke_output if command[1:] == [steam_tracking.STEAM_QUERY_WORKER_SMOKE_ARGUMENT] else normal_output
            return SimpleNamespace(returncode=0, stdout=output, stderr="")

        with mock.patch.object(build_release, "_run_tracked_build_process", side_effect=run) as mocked_run:
            build_release.smoke_test(Path("NinjaCaptureTool.exe"))
        self.assertEqual(mocked_run.call_count, 4)
        for index, call in enumerate(mocked_run.call_args_list):
            self.assertEqual(call.kwargs["env"]["NCT_HEADLESS"], "1")
            self.assertNotIn("PYINSTALLER_STRICT_UNPACK_MODE", call.kwargs["env"])
            self.assertEqual(call.kwargs["env"][common.RELEASE_BUILD_ENV], "1")
            self.assertEqual(call.kwargs["creationflags"], getattr(build_release.subprocess, "CREATE_NO_WINDOW", 0))
            self.assertEqual(call.kwargs["timeout"], 30 if index == 3 else 120)
        self.assertEqual(mocked_run.call_args_list[-1].args[0][1:], [steam_tracking.STEAM_QUERY_WORKER_SMOKE_ARGUMENT])

    def test_fallback_licenses_are_tracked_source_files(self) -> None:
        expected = {
            "python": build_release.LICENSES_DIR / "Python_LICENSE.txt",
        }
        versioned_expected = {
            ("gevent-eventemitter", "2.1"): build_release.LICENSES_DIR / "gevent_eventemitter_LICENSE.txt",
            ("mitmproxy-rs", "0.12.11"): build_release.LICENSES_DIR / "mitmproxy_rs_LICENSE.txt",
            ("publicsuffix2", "2.20191221"): build_release.LICENSES_DIR / "publicsuffix2_LICENSE.txt",
        }
        self.assertEqual(build_release.FALLBACK_LICENSE_FILES, expected)
        self.assertEqual(build_release.VERSIONED_FALLBACK_LICENSE_FILES, versioned_expected)
        for path in (*expected.values(), *versioned_expected.values()):
            self.assertTrue(path.is_file())

    def test_publicsuffix_style_license_filename_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            license_file = root / "publicsuffix2.LICENSE"
            license_file.write_text("license", encoding="utf-8")
            distribution = mock.Mock()
            distribution.files = [Path("publicsuffix2.LICENSE")]
            distribution.locate_file.side_effect = lambda item: root / Path(str(item))
            self.assertEqual(build_release.distribution_license_files(distribution), [license_file])

    def test_license_collection_uses_fallback_and_includes_python_license(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage = root / "stage"
            stage.mkdir()
            python_license = root / "PYTHON_LICENSE.txt"
            python_license.write_text("python license", encoding="utf-8")

            distribution = mock.Mock()
            distribution.metadata = {"Name": "mitmproxy_rs"}
            distribution.version = "0.12.11"
            distribution.files = []

            with (
                mock.patch.object(build_release, "find_python_license", return_value=python_license),
                mock.patch.object(build_release, "dependency_closure", return_value=[distribution]),
            ):
                build_release.collect_third_party_licenses(stage)

            licenses = stage / "data" / "licenses"
            python_copy = licenses / f"Python-{os.sys.version_info.major}.{os.sys.version_info.minor}.{os.sys.version_info.micro}-LICENSE.txt"
            self.assertEqual(python_copy.read_text(encoding="utf-8"), "python license")
            fallback_copy = licenses / "mitmproxy-rs-0.12.11-mitmproxy_rs_LICENSE.txt"
            self.assertEqual(
                fallback_copy.read_bytes(),
                build_release.VERSIONED_FALLBACK_LICENSE_FILES[("mitmproxy-rs", "0.12.11")].read_bytes(),
            )
            self.assertFalse(any(path.is_dir() for path in licenses.iterdir()))
            self.assertTrue(all(path.suffix.casefold() == ".txt" for path in licenses.iterdir()))

    def test_license_collection_uses_gevent_eventemitter_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage = root / "stage"
            stage.mkdir()
            python_license = root / "PYTHON_LICENSE.txt"
            python_license.write_text("python license", encoding="utf-8")

            distribution = mock.Mock()
            distribution.metadata = {"Name": "gevent-eventemitter"}
            distribution.version = "2.1"
            distribution.files = []

            with (
                mock.patch.object(build_release, "find_python_license", return_value=python_license),
                mock.patch.object(build_release, "dependency_closure", return_value=[distribution]),
            ):
                build_release.collect_third_party_licenses(stage)

            fallback_copy = (
                stage
                / "data"
                / "licenses"
                / "gevent-eventemitter-2.1-gevent_eventemitter_LICENSE.txt"
            )
            self.assertEqual(
                fallback_copy.read_bytes(),
                build_release.VERSIONED_FALLBACK_LICENSE_FILES[("gevent-eventemitter", "2.1")].read_bytes(),
            )

    def test_runtime_license_dedup_removes_only_exact_preserved_license_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            stage = Path(tmp) / "stage"
            runtime = stage / common.FROZEN_RUNTIME_DIR_NAME
            licenses = stage / "data" / "licenses"
            runtime_license = runtime / "package.dist-info" / "licenses" / "LICENSE"
            different_notice = runtime / "package.dist-info" / "NOTICE.txt"
            same_bytes_nonlicense = runtime / "package" / "payload.dat"
            licenses.mkdir(parents=True)
            runtime_license.parent.mkdir(parents=True)
            different_notice.parent.mkdir(parents=True, exist_ok=True)
            same_bytes_nonlicense.parent.mkdir(parents=True)

            (licenses / "package-LICENSE.txt").write_bytes(b"license bytes")
            runtime_license.write_bytes(b"license bytes")
            different_notice.write_bytes(b"different notice")
            same_bytes_nonlicense.write_bytes(b"license bytes")

            removed = build_release.remove_duplicate_runtime_license_files(stage)

            self.assertEqual(
                removed,
                [f"{common.FROZEN_RUNTIME_DIR_NAME}/package.dist-info/licenses/LICENSE"],
            )
            self.assertFalse(runtime_license.exists())
            self.assertTrue(different_notice.is_file())
            self.assertTrue(same_bytes_nonlicense.is_file())
            self.assertEqual((licenses / "package-LICENSE.txt").read_bytes(), b"license bytes")

    def test_dependency_license_names_are_normalized_to_text_files(self) -> None:
        self.assertEqual(
            build_release.normalized_license_output_name("pyasn1-0.6.4", Path("LICENSE.rst"), 1, 1),
            "pyasn1-0.6.4-LICENSE.txt",
        )
        self.assertEqual(
            build_release.normalized_license_output_name("cryptography-48.0.1", Path("LICENSE.APACHE"), 1, 2),
            "cryptography-48.0.1-1-LICENSE.APACHE.txt",
        )

    def test_release_name_is_derived_from_version(self) -> None:
        self.assertEqual(
            build_release.release_archive_path().name,
            f"NinjaCaptureTool-v{common.VERSION}-Windows-x64.zip",
        )

    def test_release_readme_is_plain_text_and_omits_build_section(self) -> None:
        markdown = (build_release.ROOT / "README.md").read_text(encoding="utf-8")
        readme = build_release.create_release_readme(markdown)
        self.assertTrue(readme.startswith(f"Ninja Capture Tool\n==================\nVersion {common.display_version()}\n"))
        self.assertNotIn("## ", readme)
        self.assertNotIn("Standalone Windows build", readme)

    def test_release_assets_require_valid_sizes(self) -> None:
        for size in (None, -1, True, "123"):
            with self.subTest(size=size):
                release = {"assets": [{"name": "asset.zip", "browser_download_url": "https://example.test/asset.zip", "size": size}]}
                with self.assertRaisesRegex(RuntimeError, "invalid or missing size"):
                    update.find_release_asset(release, "asset.zip")

    def test_release_extraction_validates_expected_layout_and_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "release.zip"
            self._write_fake_release_archive(archive, "1.2.0")
            stage = update.extract_release_archive(archive, root / "stage", "1.2.0")
            self.assertEqual((stage / "NinjaCaptureTool.exe").read_bytes(), b"main")
            self.assertEqual(
                (stage / common.FROZEN_RUNTIME_DIR_NAME / "python314.dll").read_bytes(),
                b"runtime",
            )
            self.assertTrue((stage / "data" / "licenses" / "test-LICENSE.txt").is_file())

    def test_release_extraction_requires_only_one_staged_release_worth_of_free_space(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "release.zip"
            self._write_fake_release_archive(archive, "1.2.0")
            with zipfile.ZipFile(archive, "r") as source:
                extracted_size = sum(member.file_size for member in source.infolist() if not member.is_dir())
            with mock.patch.object(update, "_ensure_free_space") as ensure_space:
                update.extract_release_archive(archive, root / "stage", "1.2.0")
            ensure_space.assert_called_once_with(root, extracted_size, "extract the update")

    def test_release_extraction_rejects_windows_unsafe_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "release.zip"
            self._write_fake_release_archive(archive, "1.2.0", {"data/CON": b"bad"})
            with self.assertRaisesRegex(RuntimeError, "Unsafe update archive path"):
                update.extract_release_archive(archive, root / "stage", "1.2.0")

    def test_release_extraction_rejects_invalid_release_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "release.zip"
            self._write_fake_release_archive(archive, "1.2.0", {"config.json": b'{"wat": true}'})
            with self.assertRaisesRegex(RuntimeError, "unknown option"):
                update.extract_release_archive(archive, root / "stage", "1.2.0")

    def test_portable_cache_files_are_not_release_source_payloads(self) -> None:
        self.assertEqual(common.warframe_version_state_file(), common.DATA_DIR / "warframe_version.json")
        self.assertEqual(common.update_state_file(), common.DATA_DIR / "update_state.json")
        release_sources = set(build_release.RELEASE_SOURCE_FILES)
        self.assertNotIn("data/warframe_version.json", release_sources)
        self.assertNotIn("data/update_state.json", release_sources)

    def test_release_manifest_removes_only_unchanged_obsolete_release_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install = root / "install"
            stage = root / "work" / "stage"
            install.mkdir(parents=True)
            stage.mkdir(parents=True)

            obsolete = install / "obsolete-runtime.txt"
            modified = install / "modified-runtime.txt"
            user_file = install / "my-notes.txt"
            obsolete.write_text("old release file", encoding="utf-8")
            modified.write_text("old release file", encoding="utf-8")
            user_file.write_text("user data", encoding="utf-8")
            old_manifest = {
                "format_version": common.RELEASE_MANIFEST_VERSION,
                "application_version": "1.0.0",
                "files": {
                    "obsolete-runtime.txt": hashlib.sha256(b"old release file").hexdigest(),
                    "modified-runtime.txt": hashlib.sha256(b"old release file").hexdigest(),
                },
            }
            (install / common.RELEASE_MANIFEST_FILE).parent.mkdir(parents=True, exist_ok=True)
            (install / common.RELEASE_MANIFEST_FILE).write_text(
                json.dumps(old_manifest), encoding="utf-8"
            )
            modified.write_text("locally modified", encoding="utf-8")

            (stage / "NinjaCaptureTool.exe").write_bytes(b"new")
            self._write_stage_release_manifest(stage, common.VERSION)
            backup, changes = update.install_staged_release(stage, install, common.VERSION)

            self.assertFalse(obsolete.exists())
            self.assertEqual(modified.read_text(encoding="utf-8"), "locally modified")
            self.assertEqual(user_file.read_text(encoding="utf-8"), "user data")
            self.assertTrue(backup.is_dir())
            update.rollback_staged_release(changes, backup)
            self.assertEqual(obsolete.read_text(encoding="utf-8"), "old release file")
            self.assertEqual(modified.read_text(encoding="utf-8"), "locally modified")
            self.assertEqual(user_file.read_text(encoding="utf-8"), "user data")

    def test_release_manifest_is_required_and_hash_verified_during_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "release.zip"
            tampered = root / "tampered.zip"
            self._write_fake_release_archive(original, "1.2.0")
            with zipfile.ZipFile(original, "r") as source, zipfile.ZipFile(tampered, "w") as destination:
                for member in source.infolist():
                    data = source.read(member)
                    if member.filename.endswith("/NinjaCaptureTool.exe"):
                        data = b"tampered"
                    destination.writestr(member.filename, data)
            with self.assertRaisesRegex(RuntimeError, "SHA-256 does not match"):
                update.extract_release_archive(tampered, root / "stage", "1.2.0")

    def test_release_builder_treats_runtime_and_resource_warnings_as_test_failures(self) -> None:
        completed = SimpleNamespace(returncode=0, stdout="", stderr="")
        with mock.patch.object(build_release.subprocess, "run", return_value=completed) as run:
            build_release.run_tests()
        command = run.call_args.args[0]
        self.assertIn("error::DeprecationWarning", command)
        self.assertIn("error::RuntimeWarning", command)
        self.assertIn("error::ResourceWarning", command)
        self.assertEqual(run.call_args.kwargs["env"]["PYTHONDONTWRITEBYTECODE"], "1")
        self.assertEqual(run.call_args.kwargs["errors"], "replace")
        self.assertEqual(run.call_args.kwargs["creationflags"], getattr(build_release.subprocess, "CREATE_NO_WINDOW", 0))

    def test_release_duration_uses_patch_summary_format(self) -> None:
        self.assertEqual(build_release.format_duration(0), "00:00")
        self.assertEqual(build_release.format_duration(65), "01:05")
        self.assertEqual(build_release.format_duration(3599), "59:59")
        self.assertEqual(build_release.format_duration(3600), "01:00:00")
        self.assertEqual(build_release.format_duration(3661), "01:01:01")

    def test_release_stage_contains_only_one_executable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            stage = Path(tmp) / "stage"
            (stage / "data" / "licenses").mkdir(parents=True)
            (stage / common.FROZEN_RUNTIME_DIR_NAME).mkdir()
            (stage / common.FROZEN_RUNTIME_DIR_NAME / "python314.dll").write_bytes(b"runtime")
            (stage / "NinjaCaptureTool.exe").write_bytes(b"exe")
            (stage / "config.json").write_text(json.dumps(nct_config.DEFAULT_CONFIG), encoding="utf-8")
            (stage / "README.txt").write_text("readme", encoding="utf-8")
            (stage / "data" / "licenses" / build_release.NCT_LICENSE_RELEASE_NAME).write_text(
                "GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007", encoding="utf-8"
            )
            (stage / "data" / "licenses" / "license.txt").write_text("license", encoding="utf-8")
            build_release.write_release_manifest(stage)
            build_release.validate_stage(stage)
            self.assertTrue((stage / "data" / "release_manifest.json").is_file())
            self.assertFalse((stage / "release_manifest.json").exists())
            self.assertFalse((stage / "LICENSE").exists())
            self.assertTrue((stage / "data" / "licenses" / build_release.NCT_LICENSE_RELEASE_NAME).is_file())
            self.assertEqual([path.name for path in stage.glob("*.exe")], ["NinjaCaptureTool.exe"])

    def test_release_stage_allows_pyinstaller_runtime_python_sources_but_rejects_extra_root_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage = self.make_release_stage(root)
            runtime_source = stage / common.FROZEN_RUNTIME_DIR_NAME / "mitmproxy" / "http.py"
            runtime_source.parent.mkdir(parents=True, exist_ok=True)
            runtime_source.write_text("# bundled runtime source\n", encoding="utf-8")
            build_release.write_release_manifest(stage)
            build_release.validate_stage(stage)

            project_source = stage / "capture.py"
            project_source.write_text("# accidental project source\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "Unexpected release staging contents"):
                build_release.validate_stage(stage)

    def test_release_archive_validates_exact_members_and_manifest_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage = root / "stage"
            (stage / "data").mkdir(parents=True)
            (stage / "NinjaCaptureTool.exe").write_bytes(b"expected-exe")
            (stage / "config.json").write_text("{}", encoding="utf-8")
            build_release.write_release_manifest(stage)
            prefix = f"NinjaCaptureTool-v{common.VERSION}/"

            valid = root / "valid.zip"
            with zipfile.ZipFile(valid, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for path in stage.rglob("*"):
                    if path.is_file():
                        archive.write(path, prefix + path.relative_to(stage).as_posix())
            build_release.validate_release_archive(valid, stage)

            extra = root / "extra.zip"
            with zipfile.ZipFile(extra, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for path in stage.rglob("*"):
                    if path.is_file():
                        archive.write(path, prefix + path.relative_to(stage).as_posix())
                archive.writestr(prefix + "unexpected.bin", b"extra")
            with self.assertRaisesRegex(RuntimeError, "member set"):
                build_release.validate_release_archive(extra, stage)

            tampered = root / "tampered.zip"
            with zipfile.ZipFile(tampered, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for path in stage.rglob("*"):
                    if not path.is_file():
                        continue
                    relative = path.relative_to(stage).as_posix()
                    payload = b"tampered" if relative == "NinjaCaptureTool.exe" else path.read_bytes()
                    archive.writestr(prefix + relative, payload)
            with self.assertRaisesRegex(RuntimeError, "hash mismatch"):
                build_release.validate_release_archive(tampered, stage)

