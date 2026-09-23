import ast

# Run from the project root with: py -B -m unittest discover -s tests
from support import *

class EntrypointTests(NctTestBase):
    def test_main_module_does_not_import_second_ninja_capture_tool_instance(self) -> None:
        entry = Path(nct.__file__).resolve()
        code = (
            "import runpy, sys\n"
            "sys.platform = 'linux'\n"
            f"entry = {str(entry)!r}\n"
            "sys.argv = [entry, '--version']\n"
            "try:\n"
            "    runpy.run_path(entry, run_name='__main__')\n"
            "except SystemExit:\n"
            "    pass\n"
            "if 'ninja_capture_tool' in sys.modules:\n"
            "    raise SystemExit('entrypoint imported a second ninja_capture_tool module')\n"
        )
        result = subprocess.run(
            [sys.executable, "-B", "-c", code],
            cwd=entry.parent,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

    def test_subsystems_do_not_import_entry_module(self) -> None:
        root = Path(nct.__file__).resolve().parent
        for name in (
            "capture.py",
            "common.py",
            "config.py",
            "elevation.py",
            "instance_lock.py",
            "check_live.py",
            "runtime.py",
            "session.py",
            "check_steam.py",
            "update.py",
            "windows_proxy.py",
        ):
            text = (root / name).read_text(encoding="utf-8")
            with self.subTest(module=name):
                self.assertNotIn("import ninja_capture_tool", text)
                self.assertNotIn("from ninja_capture_tool", text)

    def test_production_modules_do_not_redefine_top_level_functions_or_classes(self) -> None:
        root = Path(nct.__file__).resolve().parent
        duplicates: list[str] = []

        for path in sorted(root.glob("*.py"), key=lambda item: item.name.casefold()):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            definitions: dict[str, int] = {}
            for node in tree.body:
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue
                previous = definitions.get(node.name)
                if previous is None:
                    definitions[node.name] = node.lineno
                    continue
                duplicates.append(f"{path.name}:{node.lineno}: {node.name} (first defined at line {previous})")

        self.assertEqual(duplicates, [], "Duplicate top-level definitions found:\n" + "\n".join(duplicates))

    def test_production_modules_do_not_reach_into_other_modules_private_api(self) -> None:
        root = Path(nct.__file__).resolve().parent
        module_paths = tuple(sorted(root.glob("*.py"), key=lambda path: path.name.casefold()))
        project_modules = {path.stem for path in module_paths}
        violations: list[str] = []

        for path in module_paths:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            module_aliases: dict[str, str] = {}
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for imported in node.names:
                        if imported.name in project_modules:
                            module_aliases[imported.asname or imported.name] = imported.name
                elif isinstance(node, ast.ImportFrom) and node.module in project_modules:
                    for imported in node.names:
                        if imported.name.startswith("_") and not imported.name.startswith("__"):
                            violations.append(
                                f"{path.name}:{node.lineno}: from {node.module} import {imported.name}"
                            )

            for node in ast.walk(tree):
                if not isinstance(node, ast.Attribute) or not isinstance(node.value, ast.Name):
                    continue
                owner = module_aliases.get(node.value.id)
                if owner is None or not node.attr.startswith("_") or node.attr.startswith("__"):
                    continue
                violations.append(f"{path.name}:{node.lineno}: {node.value.id}.{node.attr}")

        self.assertEqual(violations, [], "Cross-module private API access found:\n" + "\n".join(violations))

