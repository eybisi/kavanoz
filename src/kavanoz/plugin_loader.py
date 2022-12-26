import sys
import pkgutil
import importlib
from pathlib import Path
from kavanoz.unpack_plugin import Unpacker

PLUGIN_DIRECTORY = Path(__file__).parent / "loader"
BLACKLISTED_KEYS = (
    "__name__",
    "__doc__",
    "__package__",
    "__loader__",
    "__spec__",
    "__file__",
    "__cached__",
    "__builtins__",
)


def dicover_plugins(path: Path):
    posix_path = PLUGIN_DIRECTORY.as_posix()
    if posix_path not in sys.path:
        sys.path.append(posix_path)

    iter_from = [posix_path]
    for finder, name, ispkg in pkgutil.iter_modules(iter_from):
        yield name


def import_plugin(module_name: str) -> list[Unpacker]:
    module = importlib.import_module(module_name)
    module_dict = module.__dict__

    check_in = None

    if "__all__" in module_dict:
        check_in = {
            key: module_dict[key]
            for key in module_dict["__all__"]
            if key in module_dict
        }
    else:
        check_in = {
            key: val for key, val in module_dict.items() if key not in BLACKLISTED_KEYS
        }

    valid_items = [
        mod
        for inner_module_name in check_in
        if (mod := module_dict[inner_module_name])
        and inner_module_name.startswith("Loader")
        and issubclass(mod, Unpacker)
    ]

    if not valid_items:
        del sys.modules[module_name]
        return None
    else:
        return valid_items


def get_plugins():
    for plugin in dicover_plugins(PLUGIN_DIRECTORY):
        yield import_plugin(plugin)
