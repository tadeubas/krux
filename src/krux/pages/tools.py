# The MIT License (MIT)

# Copyright (c) 2021-2024 Krux contributors

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import uos
from . import (
    Page,
    Menu,
    MENU_CONTINUE,
    MENU_EXIT,
    # ESC_KEY,
    # LETTERS,
    # UPPERCASE_LETTERS,
    # NUM_SPECIAL_1,
    # NUM_SPECIAL_2,
)
from .file_manager import SD_ROOT_PATH
from ..format import generate_thousands_separator
from ..sd_card import SDHandler
from ..display import BOTTOM_PROMPT_LINE
from ..krux_settings import t


# TODO: re-enable "Create a QR Code" (and keypads ^^^) once encryption is possible w/o Datum Tool


class Tools(Page):
    """Krux generic tools"""

    def __init__(self, ctx):
        super().__init__(
            ctx,
            Menu(
                ctx,
                [
                    (t("Check SD Card"), self.sd_check),
                    (t("Datum Tool"), self.datum_tool),
                    (t("Device Tests"), self.device_tests),
                    # (t("Create QR Code"), self.create_qr),
                    (t("Descriptor Addresses"), self.descriptor_addresses),
                    (t("Flash Tools"), self.flash_tools),
                    (t("Remove Mnemonic"), self.rm_stored_mnemonic),
                ],
            ),
        )
        self.ctx = ctx

    def flash_tools(self):
        """Handler for the 'Flash Tools' menu item"""

        from .flash_tools import FlashTools

        flash_tools = FlashTools(self.ctx)
        flash_tools.flash_tools_menu()
        return MENU_CONTINUE

    def sd_check(self):
        """Handler for the 'SD Check' menu item"""
        self.ctx.display.clear()
        self.ctx.display.draw_centered_text(t("Checking for SD card…"))
        try:
            # Check for SD hot-plug
            with SDHandler():
                sd_status = uos.statvfs(SD_ROOT_PATH)
                sd_total_MB = int(sd_status[2] * sd_status[1] / 1024 / 1024)
                sd_free_MB = int(sd_status[4] * sd_status[1] / 1024 / 1024)

                self.ctx.display.clear()
                self.ctx.display.draw_hcentered_text(
                    t("SD card")
                    + "\n\n"
                    + t("Size:")
                    + " "
                    + generate_thousands_separator(sd_total_MB)
                    + " MB"
                    + "\n\n"
                    + t("Used:")
                    + " "
                    + generate_thousands_separator(sd_total_MB - sd_free_MB)
                    + " MB"
                    + "\n\n"
                    + t("Free:")
                    + " "
                    + generate_thousands_separator(sd_free_MB)
                    + " MB",
                    highlight_prefix=":",
                )
                if self.prompt(t("Explore files?"), BOTTOM_PROMPT_LINE):
                    from .file_manager import FileManager

                    file_manager = FileManager(self.ctx)
                    file_manager.select_file(
                        select_file_handler=file_manager.show_file_details
                    )
        except OSError:
            self.flash_error(t("SD card not detected."))

        return MENU_CONTINUE

    def rm_stored_mnemonic(self):
        """Lists and allow deletion of stored mnemonics"""
        from .encryption_ui import LoadEncryptedMnemonic

        encrypted_mnemonics = LoadEncryptedMnemonic(self.ctx)
        while True:
            ret = encrypted_mnemonics.load_from_storage(remove_opt=True)
            if ret == MENU_CONTINUE:
                del encrypted_mnemonics
                return ret

    def datum_tool(self):
        """Handler for the 'Datum Tool' menu item"""
        import sys
        from .datum_tool import DatumToolMenu

        while True:
            if DatumToolMenu(self.ctx).run() == MENU_EXIT:
                break

        sys.modules.pop("krux.pages.datum_tool")
        del sys.modules["krux.pages"].datum_tool
        return MENU_CONTINUE

    # def create_qr(self):
    #    """Handler for the 'Create QR Code' menu item"""
    #    if self.prompt(
    #        t("Create QR code from text?"),
    #        self.ctx.display.height() // 2,
    #    ):
    #        text = self.capture_from_keypad(
    #            t("Text"), [LETTERS, UPPERCASE_LETTERS, NUM_SPECIAL_1, NUM_SPECIAL_2]
    #        )
    #        if text in ("", ESC_KEY):
    #            return MENU_CONTINUE
    #
    #        from .qr_view import SeedQRView
    #
    #        title = t("Custom QR Code")
    #        seed_qr_view = SeedQRView(self.ctx, data=text, title=title)
    #        return seed_qr_view.display_qr(allow_export=True)
    #    return MENU_CONTINUE

    def descriptor_addresses(self):
        """Handler for the 'Descriptor Addresses' menu item"""
        from .home_pages.wallet_descriptor import WalletDescriptor
        from .home_pages.addresses import Addresses
        from ..wallet import Wallet

        self.ctx.wallet = Wallet(None)
        menu_result = WalletDescriptor(self.ctx).wallet()
        if self.ctx.wallet.is_loaded():
            menu_result = Addresses(self.ctx).addresses_menu()
        return menu_result

    def device_tests(self):
        """Handler for the 'Device Tests' menu item"""
        import sys
        from .device_tests import DeviceTests

        page = DeviceTests(self.ctx)
        page.run()
        sys.modules.pop("krux.pages.device_tests")
        del sys.modules["krux.pages"].device_tests
        return MENU_CONTINUE
