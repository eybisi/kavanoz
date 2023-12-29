from androguard.core.apk import APK
from androguard.core.dex import DEX
from kavanoz.unpack_plugin import Unpacker
from kavanoz import plugin_loader
from kavanoz.utils import InterceptHandler
from loguru import logger
import logging
import time
import kavanoz.loader
import click
import sys
from halo import Halo


class Kavanoz:
    def __init__(self, apk_path=None, apk_object=None, output_dir=None):
        self.output_dir = output_dir
        s = time.time()
        if apk_object:
            self.apk_object = apk_object
        else:
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
        self.dvms = [DEX(dex) for dex in self.apk_object.get_all_dex()]
        e = time.time()
        logger.info(f"Androguard dvm took : {e-s} seconds")

    def get_plugin_results(self):
        for plugin in self.plugins:
            p = plugin(self.apk_object, self.dvms, output_dir=self.output_dir)
            yield p.main()

    def is_packed(self):
        p = Unpacker(
            "test",
            "test",
            apk_object=self.apk_object,
            dvms=self.dvms,
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
    logging.basicConfig(handlers=[InterceptHandler()], level=0, force=True)
    logger.disable("androguard")
    logger.remove()
    if verbose > 0:
        logger.add(sys.stderr, level=verbose)
    spinner = Halo(text="Extracting apk/dvm information", spinner="star")
    spinner.start()
    k = Kavanoz(filename, output_dir=output_dir)
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
