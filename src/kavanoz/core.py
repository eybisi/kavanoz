from androguard.core.apk import APK
from androguard.core.dex import DEX
from androguard import util
from kavanoz.unpack_plugin import Unpacker
from kavanoz import plugin_loader, utils
from kavanoz.utils import InterceptHandler
from loguru import logger
import logging
import time
import kavanoz.loader
import click
import sys
from halo import Halo


logger.disable("androguard")

class Kavanoz:
    def __init__(
        self,
        apk_path: str | None = None,
        apk_object=None,
        output_dir: str | None = None,
    ):
        self.output_dir = output_dir
        mod_logger = logging.getLogger("androidemu")
        mod_logger.handlers = [InterceptHandler(level=logging.CRITICAL)]
        mod_logger.propagate = False
        s = time.time()
        if apk_object:
            self.apk_object = apk_object
        elif apk_path:
            self.apk_object = APK(apk_path)

        # load plugins
        self.plugins = [
            subplug
            for plugin in filter(None, plugin_loader.get_plugins())
            for subplug in plugin
        ]
        e = time.time()
        logger.info(f"Androguard took : {e-s} seconds")
        s = time.time()
        self.dexes = [DEX(dex) for dex in self.apk_object.get_all_dex()]
        e = time.time()
        logger.info(f"Androguard dvm took : {e-s} seconds")

    def get_plugin_results(self):
        for plugin in self.plugins:
            p = plugin(self.apk_object, self.dexes, output_dir=self.output_dir)
            yield p.main()

    def is_packed(self):
        p = Unpacker(
            "test",
            "test",
            apk_object=self.apk_object,
            dexes=self.dexes,
            output_dir=self.output_dir,
        )
        return p.is_packed()


@click.command()
@click.argument("filename", type=click.Path(exists=True))
@click.option(
    "--output-dir",
    "-o",
    type=click.Path(exists=True),
    default=".",
    help="Output directory path",
)
@click.option("-v", "--verbose", count=True)
def cli(filename, output_dir, verbose):
    logger.remove()
    if verbose > 0:
        if verbose > 3:
            verbose = 3
        logger.add(sys.stderr, level=40-verbose*10)
    spinner = Halo(text="Extracting apk/dex information", spinner="star")
    spinner.start()
    k = Kavanoz(filename, output_dir=output_dir)
    logger.warning("This is a warning")
    spinner.stop()
    spinner.start()
    if not k.is_packed():
        spinner.warn("Sample is not packed")
    for res in k.get_plugin_results():
        spinner.text = f'Plugin {res["tag"]} is running'
        spinner.start()
        if res["status"] == "success":
            m = f"""Plugin tag : {res['tag']} 
Plugin description : {res['name']} 
Output file : {res['output_file']} """
            spinner.text_color = "green"
            spinner.stop_and_persist("✨", "Unpacked succesfully!")
            print(m)
            break
    else:
        spinner.stop_and_persist("❌", "Cannot unpack")
