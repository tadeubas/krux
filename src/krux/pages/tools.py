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
    ESC_KEY,
    LETTERS,
    UPPERCASE_LETTERS,
    NUM_SPECIAL_1,
    NUM_SPECIAL_2,
)
from .file_manager import SD_ROOT_PATH
from ..format import generate_thousands_separator
from ..sd_card import SDHandler
from ..display import BOTTOM_PROMPT_LINE
from ..krux_settings import t
from ..qr import FORMAT_NONE

READABLEBUFFER_SIZE = 128


class Tools(Page):
    """Krux generic tools"""

    def __init__(self, ctx):
        self.ctx = ctx

        super().__init__(
            ctx,
            Menu(
                ctx,
                [
                    (t("Check SD Card"), self.sd_check),
                    (t("Load Krux app"), self.sd_load_app),
                    (t("Print Test QR"), self.print_test),
                    (t("Create QR Code"), self.create_qr),
                    (t("Descriptor Addresses"), self.descriptor_addresses),
                    (t("Flash Tools"), self.flash_tools),
                    (t("Remove Mnemonic"), self.rm_stored_mnemonic),
                ],
            ),
        )

    def _check_signature(self, sig, data_hash):
        from embit import ec
        from ..metadata import SIGNER_PUBKEY

        pubkey = None
        try:
            pubkey = ec.PublicKey.from_string(SIGNER_PUBKEY)
        except:
            raise ValueError("Invalid public key")

        try:
            # Parse, serialize, and reparse to ensure signature is compact prior to verification
            sig = ec.Signature.parse(ec.Signature.parse(sig).serialize())

            if not pubkey.verify(sig, data_hash):
                self.flash_error(t("Bad signature"))
                return MENU_CONTINUE
        except:
            self.flash_error(t("Bad signature"))
            return MENU_CONTINUE

        return None

    def sd_load_app(self):  # pylint: disable=R1710
        """Handler for the 'Load Krux app' menu item"""
        if not self.prompt(
            t("Execute a signed Krux app?"), self.ctx.display.height() // 2
        ):
            return MENU_CONTINUE

        # Check if Krux app is enabled
        from krux.krux_settings import Settings

        if not Settings().security.allow_kapp:
            self.flash_error(t("Allow in settings first!"))
            return MENU_CONTINUE

        if not self.has_sd_card():
            self.flash_error(t("SD card not detected."))
            return MENU_CONTINUE

        # Prompt user for .mpy file
        from krux.pages.utils import Utils
        from krux.sd_card import MPY_FILE_EXTENSION, SIGNATURE_FILE_EXTENSION, SD_PATH

        filename, _ = Utils(self.ctx).load_file(
            MPY_FILE_EXTENSION, prompt=False, only_get_filename=True
        )

        if not filename:
            return MENU_CONTINUE

        # Confirm hash string
        sd_path_prefix = "/%s/" % SD_PATH
        from krux.firmware import sha256

        data_hash = sha256(sd_path_prefix + filename)

        import binascii

        self.ctx.display.clear()
        self.ctx.display.draw_hcentered_text(
            filename + "\n\n" + "SHA256:\n" + binascii.hexlify(data_hash).decode()
        )
        if not self.prompt(t("Proceed?"), BOTTOM_PROMPT_LINE):
            return MENU_CONTINUE

        # Check signature of .mpy file in SD
        sig_data = None
        try:
            sig_data = open(
                sd_path_prefix + filename + SIGNATURE_FILE_EXTENSION, "rb"
            ).read()
        except:
            self.flash_error(t("Missing signature file"))
            return MENU_CONTINUE

        if self._check_signature(sig_data, data_hash) == MENU_CONTINUE:
            return MENU_CONTINUE

        # Delete any .mpy files from flash VFS to avoid malicious code import/execution
        import os
        from krux.settings import FLASH_PATH

        found_in_flash_vfs = False
        flash_path_prefix = "/%s/" % FLASH_PATH
        for file in os.listdir(flash_path_prefix):
            if file.endswith(MPY_FILE_EXTENSION):
                # Only remove .mpy different from what was loaded from SD
                if sha256(flash_path_prefix + file) != data_hash:
                    os.remove(flash_path_prefix + file)
                else:
                    found_in_flash_vfs = True

        # Copy kapp + sig from SD to flash VFS if not found
        # sig file will allow the check and execution of the kapp at startup (opsec)
        kapp_filename = "kapp"
        if not found_in_flash_vfs:
            with open(
                flash_path_prefix + kapp_filename + MPY_FILE_EXTENSION,
                "wb",
                buffering=0,
            ) as kapp_file:
                with open(sd_path_prefix + filename, "rb", buffering=0) as file:
                    while True:
                        chunk = file.read(READABLEBUFFER_SIZE)
                        if not chunk:
                            break
                        kapp_file.write(chunk)

            with open(
                flash_path_prefix
                + kapp_filename
                + MPY_FILE_EXTENSION
                + SIGNATURE_FILE_EXTENSION,
                "wb",
            ) as kapp_sig_file:
                kapp_sig_file.write(sig_data)

        del sig_data
        import gc

        gc.collect()

        # Allows import of files in flash VFS
        # TODO: Dinamically enable vsf->execution
        os.chdir("/" + FLASH_PATH)

        # Import and exec the kapp
        i_kapp = None
        try:
            i_kapp = __import__(kapp_filename)
            i_kapp.run(self.ctx)
        except:
            # avoids importing from flash VSF
            os.chdir("/")

            # unimport module
            import sys

            del i_kapp
            del sys.modules[kapp_filename]

            raise ValueError("Could not execute %s" % filename)

        # avoids importing from flash VSF
        os.chdir("/")

        # After execution restart Krux (better safe than sorry)
        from ..power import power_manager

        power_manager.shutdown()

    def flash_tools(self):
        """Handler for the 'Flash Tools' menu item"""

        from .flash_tools import FlashTools

        flash_tools = FlashTools(self.ctx)
        flash_tools.flash_tools_menu()
        return MENU_CONTINUE

    def sd_check(self):
        """Handler for the 'SD Check' menu item"""
        self.ctx.display.clear()
        self.ctx.display.draw_centered_text(t("Checking for SD card.."))
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
                    + " MB"
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

    def print_test(self):
        """Handler for the 'Print Test QR' menu item"""
        title = t("Krux Printer Test QR")
        self.display_qr_codes(title, FORMAT_NONE, title)
        from .print_page import PrintPage

        print_page = PrintPage(self.ctx)
        print_page.print_qr(title, title=title)
        return MENU_CONTINUE

    def create_qr(self):
        """Handler for the 'Create QR Code' menu item"""
        if self.prompt(
            t("Create QR code from text?"),
            self.ctx.display.height() // 2,
        ):
            text = self.capture_from_keypad(
                t("Text"), [LETTERS, UPPERCASE_LETTERS, NUM_SPECIAL_1, NUM_SPECIAL_2]
            )
            if text in ("", ESC_KEY):
                return MENU_CONTINUE

            from .qr_view import SeedQRView

            title = t("Custom QR Code")
            seed_qr_view = SeedQRView(self.ctx, data=text, title=title)
            return seed_qr_view.display_qr(allow_export=True)
        return MENU_CONTINUE

    def descriptor_addresses(self):
        """Handler for the 'Descriptor Addresses' menu item"""
        from .home_pages.wallet_descriptor import WalletDescriptor
        from .home_pages.addresses import Addresses
        from krux.wallet import Wallet

        self.ctx.wallet = Wallet(None)
        menu_result = WalletDescriptor(self.ctx).wallet()
        if self.ctx.wallet.is_loaded():
            menu_result = Addresses(self.ctx).addresses_menu()
        return menu_result
