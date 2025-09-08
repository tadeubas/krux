import pytest
from . import create_ctx


@pytest.fixture
def mocker_printer(mocker):
    mocker.patch("krux.printers.thermal.AdafruitPrinter", new=mocker.MagicMock())


@pytest.fixture
def mock_retro_compatibility(mocker, amigo):
    from krux.settings import CategorySetting

    class MockDefaultWallet:
        namespace = "settings.wallet"
        network = CategorySetting("network", "main", ["main", "test"])
        script_type = CategorySetting("script_type", "test", ["test"])
        multisig = CategorySetting("multisig", True, [True, False])

        def label(self, _):
            pass

    mocker.patch(
        "krux.krux_settings.DefaultWallet",
        mocker.MagicMock(return_value=MockDefaultWallet()),
    )


################### Test menus


def test_menu_load_from_camera(m5stickv, mocker):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER

    BTN_SEQUENCE = (
        # Load Key from Camera
        [BUTTON_ENTER]
        +
        # QR code
        [BUTTON_ENTER]
    )

    TEST_VALUE = "Test value"
    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)
    mocker.patch.object(
        login, "load_key_from_qr_code", mocker.MagicMock(return_value=TEST_VALUE)
    )
    test_status = login.load_key()

    assert test_status == TEST_VALUE
    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)


def test_menu_load_from_manual(m5stickv, mocker):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER, BUTTON_PAGE

    BTN_SEQUENCE = (
        # Load Key from Manual
        [BUTTON_PAGE, BUTTON_ENTER]
        +
        # Load from Numbers
        [BUTTON_PAGE, BUTTON_ENTER]
        +
        # Decimal
        [BUTTON_ENTER]
    )

    TEST_VALUE = "Test value"
    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)
    mocker.patch.object(
        login, "load_key_from_digits", mocker.MagicMock(return_value=TEST_VALUE)
    )
    test_status = login.load_key()

    assert test_status == TEST_VALUE
    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)


def test_menu_new_key(m5stickv, mocker):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER

    BTN_SEQUENCE = (
        # New Key from Snapshot
        [BUTTON_ENTER]
    )

    TEST_VALUE = "Test value"
    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)
    mocker.patch.object(
        login, "new_key_from_snapshot", mocker.MagicMock(return_value=TEST_VALUE)
    )
    test_status = login.new_key()

    assert test_status == TEST_VALUE
    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)


def test_load_new_key_from_dice_module(m5stickv, mocker):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER, BUTTON_PAGE_PREV

    BTN_SEQUENCE = [
        BUTTON_PAGE_PREV,  # Go to Back
        BUTTON_ENTER,  # Exit
    ]
    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)
    login.new_key_from_dice()

    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)


def test_tools_menu(m5stickv, mocker):
    from krux.pages.login import Login, MENU_CONTINUE
    from krux.input import BUTTON_ENTER, BUTTON_PAGE

    BTN_SEQUENCE = (
        # Back
        [BUTTON_PAGE] * 6
        + [BUTTON_ENTER]
    )

    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)
    test_tools = login.tools()

    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)
    assert test_tools == MENU_CONTINUE


def test_load_setting_menu(m5stickv, mocker):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER, BUTTON_PAGE_PREV

    BTN_SEQUENCE = [
        BUTTON_PAGE_PREV,  # Go to Back
        BUTTON_ENTER,  # Exit
    ]

    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)
    login.settings()

    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)


################### Test load from storage menu


def test_load_from_storage(m5stickv, mocker):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER, BUTTON_PAGE

    BTN_SEQUENCE = (
        # Load Key from Storage
        [BUTTON_PAGE] * 2
        + [BUTTON_ENTER]
        + [
            BUTTON_ENTER,  # 1 press to continue loading key
            BUTTON_ENTER,  # 1 press to load wallet
        ]
    )

    MNEMONIC = "diet glad hat rural panther lawsuit act drop gallery urge where fit"

    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)
    mocker.patch(
        "krux.pages.encryption_ui.LoadEncryptedMnemonic.load_from_storage",
        mocker.MagicMock(return_value=MNEMONIC.split(" ")),
    )
    login.load_key()
    print(ctx.wallet.key.mnemonic)
    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)
    assert ctx.wallet.key.mnemonic == MNEMONIC


def test_new_12w_from_snapshot(m5stickv, mocker):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER

    # mocks a result of a hashed image
    mocker.patch(
        "krux.pages.capture_entropy.CameraEntropy.capture", return_value=b"\x01" * 32
    )

    BTN_SEQUENCE = (
        # 1 press to proceed to 12 words
        [BUTTON_ENTER]
        +
        # 1 press to proceed msg
        [BUTTON_ENTER]
        +
        # SHA256
        [BUTTON_ENTER]
        +
        # Words
        [BUTTON_ENTER]
        +
        # Load Wallet
        [BUTTON_ENTER]
    )
    MNEMONIC = "absurd amount doctor acoustic avoid letter advice cage absurd amount doctor adjust"
    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)
    login.new_key_from_snapshot()

    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)
    assert ctx.wallet.key.mnemonic == MNEMONIC


def test_new_24w_from_snapshot(m5stickv, mocker):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER, BUTTON_PAGE

    # mocks a result of a hashed image
    mocker.patch(
        "krux.pages.capture_entropy.CameraEntropy.capture", return_value=b"\x01" * 32
    )

    BTN_SEQUENCE = (
        # 1 move to select 24 words, 1 press  to proceed
        [BUTTON_PAGE, BUTTON_ENTER]
        +
        # 1 press to proceed msg
        [BUTTON_ENTER]
        +
        # SHA256
        [BUTTON_ENTER]
        +
        # Words 2x
        [BUTTON_ENTER, BUTTON_ENTER]
        +
        # Load Wallet
        [BUTTON_ENTER]
    )
    MNEMONIC = "absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice comic"
    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)
    login.new_key_from_snapshot()

    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)
    assert ctx.wallet.key.mnemonic == MNEMONIC


def test_new_double_mnemonic_from_snapshot(m5stickv, mocker):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER, BUTTON_PAGE
    from krux.wallet import is_double_mnemonic
    from embit.bip39 import mnemonic_from_bytes
    from krux.display import THIN_SPACE
    from krux.key import FINGERPRINT_SYMBOL

    ORIGINAL_ENTROPY = b"\x01" * 32

    # mocks a result of a hashed image
    mocker.patch(
        "krux.pages.capture_entropy.CameraEntropy.capture",
        return_value=ORIGINAL_ENTROPY,
    )

    BTN_SEQUENCE = (
        # 2 moves to select double mnemonic, 1 press  to proceed
        [BUTTON_PAGE, BUTTON_PAGE, BUTTON_ENTER]
        +
        # 1 press to proceed msg
        [BUTTON_ENTER]
        +
        # SHA256
        [BUTTON_ENTER]
        +
        # Words 2x
        [BUTTON_ENTER, BUTTON_ENTER]
        +
        # Load Wallet
        [BUTTON_ENTER]
    )
    MNEMONIC = "absurd amount doctor acoustic avoid letter advice cage absurd amount doctor adjust avoid letter advice cage absurd amount doctor acoustic avoid letter affair embark"
    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)
    login.new_key_from_snapshot()

    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)
    assert ctx.wallet.key.mnemonic == MNEMONIC
    assert is_double_mnemonic(MNEMONIC) == True
    ctx.display.draw_hcentered_text.assert_has_calls(
        [
            mocker.call(
                "BIP39 Mnemonic*\n" + FINGERPRINT_SYMBOL + THIN_SPACE + "5d4342d2", 5
            )
        ]
    )
    original_mnemonic_words = mnemonic_from_bytes(ORIGINAL_ENTROPY).split(" ")
    converted_mnemonic_words = ctx.wallet.key.mnemonic.split(" ")

    # Assert only words of indexes 11, 22 and 23 are different
    assert original_mnemonic_words[:11] == converted_mnemonic_words[:11]
    assert original_mnemonic_words[11] != converted_mnemonic_words[11]
    assert original_mnemonic_words[12:22] == converted_mnemonic_words[12:22]
    assert original_mnemonic_words[22] != converted_mnemonic_words[22]
    assert original_mnemonic_words[23] != converted_mnemonic_words[23]


########## load words from qrcode tests


def test_load_12w_camera_qrcode_words(m5stickv, mocker, mocker_printer):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER
    from krux.qr import FORMAT_NONE
    from krux.pages.qr_capture import QRCodeCapture

    BTN_SEQUENCE = (
        # 1 press to proceed with the 12 words
        [BUTTON_ENTER]
        +
        # Load the wallet
        [BUTTON_ENTER]
    )
    QR_FORMAT = FORMAT_NONE
    MNEMONIC = (
        "olympic term tissue route sense program under choose bean emerge velvet absurd"
    )

    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)
    mocker.patch.object(
        QRCodeCapture, "qr_capture_loop", new=lambda self: (MNEMONIC, QR_FORMAT)
    )
    login.load_key_from_qr_code()

    assert ctx.wallet.key.mnemonic == MNEMONIC
    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)


def test_load_12w_camera_qrcode_numbers(m5stickv, mocker, mocker_printer):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER
    from krux.qr import FORMAT_NONE
    from krux.pages.qr_capture import QRCodeCapture

    BTN_SEQUENCE = (
        # 1 press to proceed with the 12 words
        [BUTTON_ENTER]
        +
        # Load the wallet
        [BUTTON_ENTER]
    )
    QR_FORMAT = FORMAT_NONE
    MNEMONIC = (
        "olympic term tissue route sense program under choose bean emerge velvet absurd"
    )
    ENCODED_MNEMONIC = "123417871814150815661375189403220156058119360008"

    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)
    mocker.patch.object(
        QRCodeCapture, "qr_capture_loop", new=lambda self: (ENCODED_MNEMONIC, QR_FORMAT)
    )
    login.load_key_from_qr_code()

    assert ctx.wallet.key.mnemonic == MNEMONIC
    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)


def test_load_12w_camera_qrcode_binary(m5stickv, mocker, mocker_printer):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER
    from krux.qr import FORMAT_NONE
    from krux.pages.qr_capture import QRCodeCapture

    BTN_SEQUENCE = (
        # 1 press to proceed with the 12 words
        [BUTTON_ENTER]
        +
        # Load the wallet
        [BUTTON_ENTER]
    )
    QR_FORMAT = FORMAT_NONE
    C_SEED_QRs = [
        (
            b"[\xbd\x9dq\xa8\xecy\x90\x83\x1a\xff5\x9dBeE",
            "forum undo fragile fade shy sign arrest garment culture tube off merit",
        ),
        (
            b"[\xbd\x9dq\xa8\xecy\x90\x83\x1a\xff5\x9dBeE".decode("latin1"),
            "forum undo fragile fade shy sign arrest garment culture tube off merit",
        ),
        (
            b"[\xbd\x9dq\xa8\xec \x90\x83\x1a\xff5\x9dBeE".decode("latin1"),
            "forum undo fragile fade search embark arrest garment culture tube off melt",
        ),
    ]

    for c_seed_qr in C_SEED_QRs:
        ctx = create_ctx(mocker, BTN_SEQUENCE)
        login = Login(ctx)
        mocker.patch.object(
            QRCodeCapture, "qr_capture_loop", new=lambda self: (c_seed_qr[0], QR_FORMAT)
        )
        login.load_key_from_qr_code()

        assert ctx.wallet.key.mnemonic == c_seed_qr[1]
        assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)


def test_load_24w_camera_qrcode_words(m5stickv, mocker, mocker_printer):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER
    from krux.qr import FORMAT_NONE
    from krux.pages.qr_capture import QRCodeCapture

    BTN_SEQUENCE = (
        # 1 press to proceed with the 12 words
        [BUTTON_ENTER]
        +
        # 1 press to proceed with the next 12 words
        [BUTTON_ENTER]
        +
        # Load the wallet
        [BUTTON_ENTER]
    )
    QR_FORMAT = FORMAT_NONE
    MNEMONIC = "brush badge sing still venue panther kitchen please help panel bundle excess sign couch stove increase human once effort candy goat top tiny major"

    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)
    mocker.patch.object(
        QRCodeCapture, "qr_capture_loop", new=lambda self: (MNEMONIC, QR_FORMAT)
    )
    login.load_key_from_qr_code()

    assert ctx.wallet.key.mnemonic == MNEMONIC
    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)


def test_load_24w_camera_qrcode_numbers(m5stickv, mocker, mocker_printer):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER
    from krux.qr import FORMAT_NONE
    from krux.pages.qr_capture import QRCodeCapture

    BTN_SEQUENCE = (
        # 1 press to proceed with the 12 words
        [BUTTON_ENTER]
        +
        # 1 press to proceed with the next 12 words
        [BUTTON_ENTER]
        +
        # Load the wallet
        [BUTTON_ENTER]
    )
    QR_FORMAT = FORMAT_NONE
    MNEMONIC = "brush badge sing still venue panther kitchen please help panel bundle excess sign couch stove increase human once effort candy goat top tiny major"
    ENCODED_MNEMONIC = "023301391610171019391278098413310856127602420628160203911717091708861236056502660800183118111075"

    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)
    mocker.patch.object(
        QRCodeCapture, "qr_capture_loop", new=lambda self: (ENCODED_MNEMONIC, QR_FORMAT)
    )
    login.load_key_from_qr_code()

    assert ctx.wallet.key.mnemonic == MNEMONIC
    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)


def test_load_24w_camera_qrcode_binary(m5stickv, mocker, mocker_printer):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER
    from krux.qr import FORMAT_NONE
    from krux.pages.qr_capture import QRCodeCapture

    BTN_SEQUENCE = (
        # 1 press to proceed with the 12 words
        [BUTTON_ENTER]
        +
        # 1 press to proceed with the next 12 words
        [BUTTON_ENTER]
        +
        # Load the wallet
        [BUTTON_ENTER]
    )
    QR_FORMAT = FORMAT_NONE
    MNEMONIC = "attack pizza motion avocado network gather crop fresh patrol unusual wild holiday candy pony ranch winter theme error hybrid van cereal salon goddess expire"
    BINARY_MNEMONIC = b"\x0et\xb6A\x07\xf9L\xc0\xcc\xfa\xe6\xa1=\xcb\xec6b\x15O\xecg\xe0\xe0\t\x99\xc0x\x92Y}\x19\n"

    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)
    mocker.patch.object(
        QRCodeCapture, "qr_capture_loop", new=lambda self: (BINARY_MNEMONIC, QR_FORMAT)
    )
    login.load_key_from_qr_code()

    assert ctx.wallet.key.mnemonic == MNEMONIC
    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)


def test_load_12w_camera_qrcode_format_ur(m5stickv, mocker, mocker_printer):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER
    from krux.qr import FORMAT_UR
    from krux.pages.qr_capture import QRCodeCapture
    import binascii
    from ur.ur import UR

    BTN_SEQUENCE = (
        # 1 press to proceed with the 12 words
        [BUTTON_ENTER]
        +
        # Load the wallet
        [BUTTON_ENTER]
    )
    QR_FORMAT = FORMAT_UR
    UR_DATA = UR(
        "crypto-bip39",
        bytearray(
            binascii.unhexlify(
                "A2018C66736869656C646567726F75706565726F6465656177616B65646C6F636B6773617573616765646361736865676C6172656477617665646372657765666C616D6565676C6F76650262656E"
            )
        ),
    )
    MNEMONIC = "shield group erode awake lock sausage cash glare wave crew flame glove"

    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)
    mocker.patch.object(
        QRCodeCapture, "qr_capture_loop", new=lambda self: (UR_DATA, QR_FORMAT)
    )
    login.load_key_from_qr_code()

    assert ctx.wallet.key.mnemonic == MNEMONIC
    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)


def test_load_camera_fails_on_decrypt_kef_key_error(mocker, m5stickv):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER, BUTTON_PAGE, BUTTON_PAGE_PREV
    from krux.pages.qr_capture import QRCodeCapture
    from krux.pages import MENU_CONTINUE

    # nonsensical 0x8f byte encrypted w/ key="a" to test decryption failure
    mocker.patch.object(
        QRCodeCapture,
        "qr_capture_loop",
        new=lambda self: (
            b"\x06binkey\x05\x01\x88WB\xb9\xab\xb6\xe9\x83\x97y\x1ab\xb0F\xe2|\xd3E\x84\x2b\x2c",
            0,
        ),
    )

    btn_seq = [
        BUTTON_ENTER,  # confirm decrypt
        BUTTON_ENTER,  # type key
        BUTTON_PAGE,  # to "b"
        BUTTON_ENTER,  # enter "b"
        BUTTON_PAGE_PREV,  # back to "a"
        BUTTON_PAGE_PREV,  # back to Go
        BUTTON_ENTER,  # go Go
        BUTTON_ENTER,  # confirm key "b" (while "a" is correct key)
    ]
    ctx = create_ctx(mocker, btn_seq)
    login = Login(ctx)
    assert login.load_key_from_qr_code() == MENU_CONTINUE
    assert ctx.input.wait_for_button.call_count == len(btn_seq)
    ctx.display.flash_text.assert_called_with(
        "Failed to decrypt", 248, 2000, highlight_prefix=""
    )


############### load words from text tests


def test_load_key_from_text(m5stickv, mocker):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER, BUTTON_PAGE

    cases = [
        (
            [BUTTON_ENTER]
            + (
                # A
                [BUTTON_ENTER]
                +
                # B
                [BUTTON_ENTER]
                +
                # I
                [BUTTON_ENTER]
                +
                # Confirm
                [BUTTON_ENTER]
            )
            * 11
            + (
                # N
                [BUTTON_PAGE for _ in range(13)]
                + [BUTTON_ENTER]
                +
                # O
                [BUTTON_ENTER]
                +
                # R
                [BUTTON_PAGE, BUTTON_ENTER]
                +
                # T
                [BUTTON_ENTER]
                +
                # Go
                [BUTTON_ENTER]
            )
            + [
                BUTTON_ENTER,  # Done?
                BUTTON_ENTER,  # 12 word confirm
                BUTTON_ENTER,  # Load wallet
            ],
            "ability ability ability ability ability ability ability ability ability ability ability north",
        ),
        (
            [BUTTON_ENTER]
            + (
                # A
                [BUTTON_ENTER]
                +
                # B
                [BUTTON_ENTER]
                +
                # I
                [BUTTON_ENTER]
                +
                # Confirm
                [BUTTON_ENTER]
            )
            * 11
            +
            # Go + Confirm word
            [BUTTON_PAGE for _ in range(28)]
            + [BUTTON_ENTER]  # A
            + [BUTTON_PAGE, BUTTON_ENTER]  # C
            + [BUTTON_PAGE, BUTTON_PAGE, BUTTON_ENTER]  # I
            + [BUTTON_ENTER]  # Go
            + [
                BUTTON_ENTER,  # Done?
                BUTTON_ENTER,  # 12 word confirm
                BUTTON_ENTER,  # Load wallet
            ],
            "ability ability ability ability ability ability ability ability ability ability ability acid",
        ),
    ]
    num = 0
    for case in cases:
        print(num)
        num += 1
        ctx = create_ctx(mocker, case[0])
        login = Login(ctx)

        login.load_key_from_text()

        assert ctx.input.wait_for_button.call_count == len(case[0])
        assert ctx.wallet.key.mnemonic == case[1]


def test_load_key_from_text_on_amigo_tft_with_touch(amigo, mocker, mocker_printer):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER, BUTTON_TOUCH

    cases = [
        (
            [BUTTON_ENTER]
            + (
                # A
                [BUTTON_ENTER]
                +
                # B
                [BUTTON_ENTER]
                +
                # I
                [BUTTON_ENTER]
                +
                # Confirm
                [BUTTON_ENTER]
            )
            * 11
            + (
                # N
                [BUTTON_TOUCH]  # index 13 -> "n"
                + [BUTTON_TOUCH]  # index 14 -> "o"
                + [BUTTON_TOUCH]  # index 17 -> "r"
                +
                # Touch on del
                [BUTTON_TOUCH]  # index 27 -> "Del"
                +
                # Invalid Position
                [BUTTON_TOUCH]  # index 26 "empty"
                + [BUTTON_TOUCH]  # index 17 -> "r"
                + [BUTTON_TOUCH]  # index 19 -> "t"
                +
                # Confirm word <north> -> index 0 (Yes)
                [BUTTON_TOUCH]
            )
            +
            # Done? Confirm, Words correct? Confirm, No passphrase, Single-sig
            [
                BUTTON_ENTER,
                BUTTON_ENTER,
                BUTTON_ENTER,  # Load wallet
            ],
            "ability ability ability ability ability ability ability ability ability ability ability north",
            [13, 14, 17, 27, 26, 17, 19, 1],
        ),
    ]

    num = 0
    for case in cases:
        num = num + 1
        print(num)

        ctx = create_ctx(mocker, case[0], touch_seq=case[2])

        login = Login(ctx)
        login.load_key_from_text()

        assert ctx.input.wait_for_button.call_count == len(case[0])
        assert ctx.wallet.key.mnemonic == case[1]


def test_create_key_from_text(m5stickv, mocker):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER, BUTTON_PAGE

    cases = [
        (
            [BUTTON_ENTER]  # 12 words
            + [BUTTON_ENTER]  # Proceed
            + (
                # A
                [BUTTON_ENTER]
                +
                # B
                [BUTTON_ENTER]
                +
                # I
                [BUTTON_ENTER]
                +
                # Confirm
                [BUTTON_ENTER]
            )
            * 11
            + [BUTTON_ENTER]  # Skip blank message
            + (
                # N
                [BUTTON_PAGE for _ in range(13)]
                + [BUTTON_ENTER]
                +
                # O
                [BUTTON_ENTER]
                +
                # R
                [BUTTON_ENTER]
                +
                # Confirm "North"
                [BUTTON_ENTER]
            )
            + [
                BUTTON_ENTER,  # 12 word confirm
                BUTTON_ENTER,  # Load wallet
            ],
            "ability ability ability ability ability ability ability ability ability ability ability north",
        ),
    ]
    num = 0
    for case in cases:
        print(num)
        num += 1
        ctx = create_ctx(mocker, case[0])
        login = Login(ctx)

        login.load_key_from_text(new=True)

        assert ctx.input.wait_for_button.call_count == len(case[0])
        assert ctx.wallet.key.mnemonic == case[1]


############## load words from digits tests


def test_load_key_from_digits(m5stickv, mocker, mocker_printer):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER, BUTTON_PAGE, BUTTON_PAGE_PREV

    cases = [
        (
            [BUTTON_ENTER]  # 1 press confirm msg
            + [BUTTON_PAGE_PREV]  # place on btn Go
            + [BUTTON_ENTER]  # press Go without any value should not present any error
            + (
                # 1 press change to number "2" and 1 press to select
                [BUTTON_PAGE, BUTTON_ENTER]
                +
                # 11 press to place on btn Go
                [BUTTON_PAGE] * 11
                + [
                    BUTTON_ENTER,
                    BUTTON_ENTER,
                ]  # 1 press to select and 1 press to confirm
            )
            * 11  # repeat selection of word=2 (ability) eleven times
            + (
                # 1
                [BUTTON_ENTER]
                +
                # 2
                [BUTTON_PAGE, BUTTON_ENTER]
                +
                # 0
                [BUTTON_PAGE] * 8
                + [BUTTON_ENTER]
                +
                # 3
                [BUTTON_PAGE] * 6
                + [BUTTON_ENTER]
                # Confirm twelve word=1203 (north)
                + [BUTTON_ENTER]
            )
            + [
                BUTTON_ENTER,  # Done?
                BUTTON_ENTER,  # 12 numbers confirm
                BUTTON_ENTER,  # 12 word confirm
                BUTTON_ENTER,  # Load wallet
            ],
            "ability ability ability ability ability ability ability ability ability ability ability north",
        ),
        (
            [BUTTON_ENTER]  # 1 press confirm msg
            + (
                # 1 press change to number "2" and 1 press to select
                [BUTTON_PAGE, BUTTON_ENTER]
                +
                # 10 press to place on btn Go
                [BUTTON_PAGE] * 11
                + [
                    BUTTON_ENTER,
                    BUTTON_ENTER,
                ]  # 1 press to select and 1 press to confirm
            )
            * 11  # repeat selection of word=2 (ability) eleven times
            + (
                # 1
                [BUTTON_ENTER]
                +
                # 6
                [BUTTON_PAGE] * 5
                + [BUTTON_ENTER]
                +
                # Go
                [BUTTON_PAGE] * 7
                + [BUTTON_ENTER]
                # Confirm
                + [BUTTON_ENTER]
            )
            + [
                BUTTON_ENTER,  # Done?
                BUTTON_ENTER,  # 12 numbers confirm
                BUTTON_ENTER,  # 12 word confirm
                BUTTON_ENTER,  # Load wallet
            ],
            "ability ability ability ability ability ability ability ability ability ability ability acid",
        ),
    ]
    num = 0
    for case in cases:
        print("case:", num)
        num = num + 1
        ctx = create_ctx(mocker, case[0])
        login = Login(ctx)

        login.load_key_from_digits()

        assert ctx.input.wait_for_button.call_count == len(case[0])
        assert ctx.wallet.key.mnemonic == case[1]


def test_cancel_load_key_from_digits(m5stickv, mocker):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER, BUTTON_PAGE, BUTTON_PAGE_PREV

    case = [
        [BUTTON_ENTER]  # 1 press confirm msg
        + (
            # 1 press change to number "2" and 1 press to select
            [BUTTON_PAGE, BUTTON_ENTER]
            +
            # 2 press to place on btn Go
            [BUTTON_PAGE_PREV] * 2
            + [
                BUTTON_ENTER,
                BUTTON_ENTER,
            ]  # 1 press to select and 1 press to confirm
        )
        * 11  # repeat selection of word=2 (ability) eleven times
        + (
            # 1
            [BUTTON_ENTER]
            +
            # 6
            [BUTTON_PAGE] * 5
            + [BUTTON_ENTER]
            +
            # Go
            [BUTTON_PAGE] * 7
            + [BUTTON_ENTER]
            # Confirm
            + [BUTTON_ENTER]
        )
        + [
            BUTTON_ENTER,  # Done? - no confirmation (hide mnemonic enabled)
            BUTTON_PAGE,  # Cancel 12w confirmation
        ]
    ]

    ctx = create_ctx(mocker, case[0])
    login = Login(ctx)
    login.load_key_from_digits()

    assert ctx.input.wait_for_button.call_count == len(case[0])
    assert ctx.wallet is None


def test_load_key_from_digits_hide_mnemonic(m5stickv, mocker):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER, BUTTON_PAGE
    from krux.krux_settings import Settings

    case = (
        [BUTTON_ENTER]  # 1 press confirm msg
        + (
            # 1 press change to number "2" and 1 press to select
            [BUTTON_PAGE, BUTTON_ENTER]
            +
            # 10 press to place on btn Go
            [BUTTON_PAGE] * 11
            + [
                BUTTON_ENTER,
                BUTTON_ENTER,
            ]  # 1 press to select and 1 press to confirm
        )
        * 11  # repeat selection of word=2 (ability) eleven times
        + (
            # 1
            [BUTTON_ENTER]
            +
            # 6
            [BUTTON_PAGE] * 5
            + [BUTTON_ENTER]
            +
            # Go
            [BUTTON_PAGE] * 7
            + [BUTTON_ENTER]
            # Confirm
            + [BUTTON_ENTER]
        )
        + [
            BUTTON_ENTER,  # Done? - no confirmation (hide mnemonic enabled)
            BUTTON_ENTER,  # Load wallet
        ],
        "ability ability ability ability ability ability ability ability ability ability ability acid",
    )

    # Test with hidden mnemonic setting enabled
    Settings().security.hide_mnemonic = True

    ctx = create_ctx(mocker, case[0])
    login = Login(ctx)
    login.load_key_from_digits()

    assert ctx.input.wait_for_button.call_count == len(case[0])
    assert ctx.wallet.key.mnemonic == case[1]


def test_load_12w_from_hexadecimal(m5stickv, mocker, mocker_printer):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER, BUTTON_PAGE, BUTTON_PAGE_PREV

    BTN_SEQUENCE = (
        [BUTTON_ENTER]  # 1 press confirm msg
        + [BUTTON_PAGE_PREV]  # place on btn Go
        + [BUTTON_ENTER]  # press Go without any value should not present any error
        + (
            # 4 press change to number "F"
            [BUTTON_PAGE_PREV, BUTTON_PAGE_PREV, BUTTON_PAGE_PREV, BUTTON_PAGE_PREV]
            + [BUTTON_ENTER]  # 1 press to select F
            + [BUTTON_ENTER]  # 1 press to select F again
            + [BUTTON_ENTER]  # 1 press to confirm word=FF(255 decimal) cabin
        )
        * 11  # repeat selection of word=FF(255, cabin) eleven times
        + (
            [BUTTON_ENTER]  # 1 press to number 1
            + [BUTTON_ENTER]  # 1 press to number 1
            + [BUTTON_PAGE for _ in range(4)]  # 4 press change to number 5
            + [BUTTON_ENTER]  # 1 press to select 5
            + [BUTTON_ENTER]  # Confirm word=115(277 decimal) card
        )
        + [
            BUTTON_ENTER,  # Done?
            BUTTON_ENTER,  # 12 numbers confirm
            BUTTON_ENTER,  # 12 word confirm
            BUTTON_ENTER,  # Load wallet
        ]
    )
    MNEMONIC = "cabin cabin cabin cabin cabin cabin cabin cabin cabin cabin cabin card"

    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)

    login.load_key_from_hexadecimal()

    assert ctx.wallet.key.mnemonic == MNEMONIC
    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)


def test_possible_letters_from_hexadecimal(m5stickv, mocker, mocker_printer):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER, BUTTON_PAGE, BUTTON_PAGE_PREV

    BTN_SEQUENCE = (
        [BUTTON_ENTER]  # 1 press confirm msg
        + (
            # 7 press change to number "8"
            [
                BUTTON_PAGE,
                BUTTON_PAGE,
                BUTTON_PAGE,
                BUTTON_PAGE,
                BUTTON_PAGE,
                BUTTON_PAGE,
                BUTTON_PAGE,
            ]
            + [BUTTON_ENTER]  # 1 press to select 8
            +
            # 8 press change to number "0"
            [
                BUTTON_PAGE_PREV,
                BUTTON_PAGE_PREV,
                BUTTON_PAGE_PREV,
                BUTTON_PAGE_PREV,
                BUTTON_PAGE_PREV,
                BUTTON_PAGE_PREV,
                BUTTON_PAGE_PREV,
                BUTTON_PAGE_PREV,
            ]
            + [BUTTON_ENTER]  # 1 press to select 0
            +
            # 3 press change to btn "Go" (all other numbers are disabled)
            [
                BUTTON_PAGE,
                BUTTON_PAGE,
                BUTTON_PAGE,
            ]
            + [BUTTON_ENTER]  # 1 press to select Go
            + [BUTTON_ENTER]  # 1 press to confirm word=80(128 decimal) avocado
        )
        * 11  # repeat selection of word=80(128, avocado) eleven times
        + (
            [BUTTON_PAGE] * 4  # 4 presses to change to 5
            + [BUTTON_ENTER]  # 1 press to select 5
            + [BUTTON_PAGE_PREV] * 6  # 6 press change to btn Go
            + [BUTTON_ENTER]  # 1 press to select Go
            + [BUTTON_ENTER]  # Confirm "above"
        )
        + [
            BUTTON_ENTER,  # Done?
            BUTTON_ENTER,  # 12 numbers confirm
            BUTTON_ENTER,  # 12 word confirm
            BUTTON_ENTER,  # Load wallet
        ]
    )
    MNEMONIC = "avocado avocado avocado avocado avocado avocado avocado avocado avocado avocado avocado above"

    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)

    login.load_key_from_hexadecimal()

    assert ctx.wallet.key.mnemonic == MNEMONIC
    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)


def test_load_12w_from_octal(m5stickv, mocker, mocker_printer):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER, BUTTON_PAGE, BUTTON_PAGE_PREV

    BTN_SEQUENCE = (
        [BUTTON_ENTER]  # 1 press confirm msg
        + [BUTTON_PAGE_PREV]  # place on btn Go
        + [BUTTON_ENTER]  # press Go without any value should not present any error
        + (
            # 4 press change to number "7"
            [BUTTON_PAGE_PREV] * 4
            + [BUTTON_ENTER]  # 1 press to select 7
            + [BUTTON_ENTER]  # 1 press to select 7 again
            + [BUTTON_ENTER]  # 1 press to select 7 again
            + [BUTTON_ENTER]  # 1 press to confirm word=777(511 decimal) divert
        )
        * 11  # repeat selection of word=777(511, divert) eleven times
        + (
            [BUTTON_ENTER]  # 1 press to select 1
            + [BUTTON_PAGE] * 4  # 4 press change to number 5
            + [BUTTON_ENTER]  # 1 press to number 5
            + [BUTTON_PAGE_PREV] * 3  # 3 press change to number 2
            + [BUTTON_ENTER]  # 1 press to select 2
            + [BUTTON_PAGE] * 2  # 2 press change to number 4
            + [BUTTON_ENTER]  # 1 press to select 4
            + [BUTTON_ENTER]  # Confirm word=1524(852 decimal) heavy
        )
        + [
            BUTTON_ENTER,  # Done
            BUTTON_ENTER,  # 12 numbers confirm
            BUTTON_ENTER,  # 12 word confirm
            BUTTON_ENTER,  # Load wallet
        ]
    )
    MNEMONIC = "divert divert divert divert divert divert divert divert divert divert divert heavy"

    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)

    login.load_key_from_octal()

    assert ctx.wallet.key.mnemonic == MNEMONIC
    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)


def test_possible_letters_from_octal(m5stickv, mocker, mocker_printer):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER, BUTTON_PAGE, BUTTON_PAGE_PREV

    BTN_SEQUENCE = (
        [BUTTON_ENTER]  # 1 press confirm msg
        + (
            # 3 press change to number "4"
            [
                BUTTON_PAGE,
                BUTTON_PAGE,
                BUTTON_PAGE,
            ]
            + [BUTTON_ENTER]  # 1 press to select 4
            +
            # 4 press change to number "0"
            [
                BUTTON_PAGE_PREV,
                BUTTON_PAGE_PREV,
                BUTTON_PAGE_PREV,
                BUTTON_PAGE_PREV,
            ]
            + [BUTTON_ENTER]  # 1 press to select 0
            + [BUTTON_ENTER]  # 1 press to select 0
            +
            # 3 press change to btn "Go" (all other numbers are disabled)
            [
                BUTTON_PAGE,
                BUTTON_PAGE,
                BUTTON_PAGE,
            ]
            + [BUTTON_ENTER]  # 1 press to select Go
            + [BUTTON_ENTER]  # 1 press to confirm word=400(256 decimal) cable
        )
        * 11  # repeat selection of word=400(256, cable) eleven times
        + (
            [BUTTON_ENTER]  # 1 press select 1
            + [BUTTON_PAGE] * 5  # 5 presses to change to 6
            + [BUTTON_ENTER]  # 1 press to select 6
            + [BUTTON_PAGE] * 4  # 4 presses to change to Go
            + [BUTTON_ENTER]  # 1 press to select Go
            + [BUTTON_ENTER]  # Confirm word=16(14 decimal) accuse
        )
        + [
            BUTTON_ENTER,  # Done?
            BUTTON_ENTER,  # 12 numbers confirm
            BUTTON_ENTER,  # 12 word confirm
            BUTTON_ENTER,  # Load wallet
        ]
    )
    MNEMONIC = (
        "cable cable cable cable cable cable cable cable cable cable cable accuse"
    )

    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)

    login.load_key_from_octal()

    assert ctx.wallet.key.mnemonic == MNEMONIC
    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)


def test_leaving_keypad(mocker, amigo):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER, BUTTON_PAGE_PREV

    BTN_SEQUENCE = [
        BUTTON_ENTER,  # Proceed
        BUTTON_PAGE_PREV,  # Move to Go
        BUTTON_PAGE_PREV,  # Move to ESC
        BUTTON_ENTER,  # Press ESC
        BUTTON_ENTER,  # Leave
    ]
    ctx = create_ctx(mocker, BTN_SEQUENCE)

    login = Login(ctx)
    login.load_key_from_text()
    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)


def test_no_passphrase_on_amigo(mocker, amigo):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER, BUTTON_PAGE

    case = (
        [BUTTON_ENTER]
        + (
            # A
            [BUTTON_ENTER]
            +
            # B
            [BUTTON_ENTER]
            +
            # I
            [BUTTON_ENTER]
            +
            # Confirm
            [BUTTON_ENTER]
        )
        * 11
        + [BUTTON_ENTER]  # A
        + [BUTTON_PAGE, BUTTON_ENTER]  # C
        + [BUTTON_PAGE, BUTTON_PAGE, BUTTON_ENTER]  # I
        + [BUTTON_ENTER]  # Go
        + [BUTTON_ENTER]  # Done?
        + [BUTTON_ENTER]  # 12 word confirm
        + [BUTTON_ENTER]  # Load wallet
    )

    ctx = create_ctx(mocker, case)
    login = Login(ctx)
    login.load_key_from_text()
    assert ctx.input.wait_for_button.call_count == len(case)


def test_passphrase(amigo, mocker, mocker_printer):
    from krux.pages.login import Login
    from krux.input import (
        BUTTON_ENTER,
        BUTTON_PAGE,
        BUTTON_PAGE_PREV,
        SWIPE_LEFT,
        SWIPE_RIGHT,
    )

    case = (
        [BUTTON_ENTER]
        + (
            # A
            [BUTTON_ENTER]
            +
            # B
            [BUTTON_ENTER]
            +
            # I
            [BUTTON_ENTER]
            +
            # Confirm
            [BUTTON_ENTER]
        )
        * 11
        + [BUTTON_ENTER]  # A
        + [BUTTON_PAGE, BUTTON_ENTER]  # C
        + [BUTTON_PAGE, BUTTON_PAGE, BUTTON_ENTER]  # I
        + [BUTTON_ENTER]  # Go
        + [BUTTON_ENTER]  # Done?
        + [BUTTON_ENTER]  # 12 word confirm
        +
        # Passphrase, confirm
        [BUTTON_PAGE, BUTTON_ENTER, BUTTON_ENTER]
        +
        # In passphrase keypad:
        [
            SWIPE_RIGHT,  # Test keypad swaping
            BUTTON_ENTER,  # Add "+" character
            SWIPE_LEFT,  #
            BUTTON_ENTER,  # Add "a" character
            BUTTON_PAGE_PREV,  # Move to Go
            BUTTON_ENTER,  # Press Go
            BUTTON_ENTER,  # Confirm passphrase
            BUTTON_ENTER,  # Load Wallet
        ]
    )

    ctx = create_ctx(mocker, case)
    login = Login(ctx)
    login.load_key_from_text()
    assert ctx.input.wait_for_button.call_count == len(case)


############### load words from tiny seed (bits)


def test_load_12w_from_tiny_seed(amigo, mocker, mocker_printer):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER, BUTTON_PAGE_PREV

    BTN_SEQUENCE = (
        [BUTTON_ENTER]  # 1 press 12w
        + [BUTTON_PAGE_PREV]  # 1 press to change to "Go"
        + [BUTTON_ENTER]  # 1 press to select Go
        + [
            BUTTON_ENTER,  # 12 word confirm
            BUTTON_ENTER,  # Load wallet
        ]
    )
    MNEMONIC = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo daring"

    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)

    login.load_key_from_tiny_seed()

    assert ctx.wallet.key.mnemonic == MNEMONIC
    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)


def test_load_24w_from_tiny_seed(m5stickv, mocker, mocker_printer):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER, BUTTON_PAGE, BUTTON_PAGE_PREV

    BTN_SEQUENCE = (
        [BUTTON_PAGE]  # 1 press to change to 24w
        + [BUTTON_ENTER]  # 1 press select 24w
        + [BUTTON_PAGE]  # 1 press to change to bit 1024
        + [BUTTON_ENTER]  # 1 press to select bit 1024
        + [BUTTON_PAGE_PREV for _ in range(2)]  # 2 press to change to "Go"
        + [BUTTON_ENTER]  # 1 press to select Go screen 12w
        + [BUTTON_ENTER]  # 1 press to select Go screen 24w
        + [
            BUTTON_ENTER,  # 12 word confirm
            BUTTON_ENTER,  # 24 word confirm
            BUTTON_ENTER,  # Load wallet
        ]
    )
    MNEMONIC = "lend zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo blossom"

    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)

    login.load_key_from_tiny_seed()

    assert ctx.wallet.key.mnemonic == MNEMONIC
    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)


def test_load_key_from_tiny_seed_scanner_12w(m5stickv, mocker):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER

    BTN_SEQUENCE = (
        [BUTTON_ENTER]  # 12 words
        + [BUTTON_ENTER]  # Confirm
        + [
            BUTTON_ENTER,  # 12 word confirm
            BUTTON_ENTER,  # Load wallet
        ]
    )
    MNEMONIC = (
        "idle item three donate heavy auto worry mass casual wrestle shock orphan"
    )

    mocker.patch(
        "krux.pages.tiny_seed.TinyScanner.scanner",
        new=mocker.MagicMock(return_value=MNEMONIC.split()),
    )
    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)
    login.load_key_from_tiny_seed_image()

    assert ctx.wallet.key.mnemonic == MNEMONIC
    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)


def test_load_12w_from_1248(m5stickv, mocker, mocker_printer):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER, BUTTON_PAGE, BUTTON_PAGE_PREV

    BTN_SEQUENCE = (
        (
            [BUTTON_ENTER]  # 1 press select first column num 1
            + [BUTTON_PAGE_PREV]  # 1 press to change to "Go"
            + [BUTTON_ENTER]  # 1 press to select Go
            + [BUTTON_ENTER]  # 1 press to confirm word 1000 language
        )
        * 11  # do this eleven times
        + [BUTTON_PAGE for _ in range(2)]  # 2 press to change second column num 1
        + [BUTTON_ENTER]  # 1 press to select second column num 1
        + [BUTTON_PAGE for _ in range(5)]  # 5 press to change third column num 2
        + [BUTTON_ENTER]  # 1 press to select third column num 2
        + [BUTTON_PAGE for _ in range(8)]  # 8 press to change to "Go"
        + [BUTTON_ENTER]  # 1 press to select Go
        + [BUTTON_ENTER]  # 1 press to confirm word 120 auction
        + [
            BUTTON_ENTER,  # Done?
            BUTTON_ENTER,  # 12 word confirm
            BUTTON_ENTER,  # Load wallet
        ]
    )
    MNEMONIC = "language language language language language language language language language language language auction"

    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)

    login.load_key_from_1248()

    assert ctx.wallet.key.mnemonic == MNEMONIC
    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)


def test_customization_while_loading_wallet(amigo, mocker):
    import sys
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER, BUTTON_PAGE, BUTTON_PAGE_PREV

    BTN_SEQUENCE = (
        [BUTTON_ENTER]  # Confirm words
        + [BUTTON_PAGE] * 2  # Move to "Customize"
        + [BUTTON_ENTER]  # Select "Customize"
        + [BUTTON_PAGE_PREV]  # Move to Back
        + [BUTTON_ENTER]  # Select Back
        + [BUTTON_PAGE_PREV]  # Move to Back
        + [BUTTON_ENTER]  # Select Back to leave
        + [BUTTON_ENTER]  # Confirm
    )

    MNEMONIC = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo daring"

    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)
    login._load_key_from_words(MNEMONIC.split())

    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)
    # Assert that the wallet settings module was loaded
    assert "krux.pages.wallet_settings" in sys.modules


def test_about(mocker, multiple_devices):
    from krux.pages.login import Login
    import board
    from krux.metadata import VERSION
    from krux.input import BUTTON_ENTER
    from krux.kboard import kboard
    from krux.qr import FORMAT_NONE

    BTN_SEQUENCE = [
        BUTTON_ENTER,  # past qr_code
    ]

    ctx = create_ctx(mocker, BTN_SEQUENCE)

    login = Login(ctx)
    mocker.spy(login, "display_qr_codes")

    login.about()

    title = "selfcustody.github.io/krux"
    msg = (
        title
        + "\n"
        + ("Hardware")
        + ": %s\n" % board.config["type"]
        + ("Version")
        + ": %s" % VERSION
    )
    display_qr_codes_call = [
        mocker.call(
            title,
            FORMAT_NONE,
            msg,
            offset_x=0,
            width=0,
            highlight_prefix=":",
        ),
    ]

    if kboard.is_cube:
        print(ctx.display.width())
        display_qr_codes_call = [
            mocker.call(
                title,
                FORMAT_NONE,
                msg,
                offset_x=ctx.display.width() // 4,
                width=ctx.display.width() // 2,
                highlight_prefix=":",
            ),
        ]
    login.display_qr_codes.assert_has_calls(display_qr_codes_call)

    ctx.display.draw_hcentered_text.assert_has_calls(
        [
            mocker.call(msg, 250, highlight_prefix=":"),
        ]
    )

    ctx.input.wait_for_button.assert_called()
    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)


def test_auto_complete_qr_words(m5stickv, mocker):
    from krux.pages.login import Login

    ctx = create_ctx(mocker, [])
    login = Login(ctx)

    # Test case where all words are valid
    words = ["abandon"] * 12
    result = login.auto_complete_qr_words(words)
    assert result == words

    # Test case where some words need to be autocompleted
    words = ["abandon", "abil", "abl"] + ["abandon"] * 9
    expected_result = ["abandon", "ability", "able"] + ["abandon"] * 9
    result = login.auto_complete_qr_words(words)
    assert result == expected_result

    # Test case where a word cannot be autocompleted
    words = ["aband", "abil", "xyz"] + ["abandon"] * 9
    result = login.auto_complete_qr_words(words)
    assert result == []

    # Test case where all words need to be autocompleted
    words = ["aband", "abil", "abl"] + ["abandon"] * 9
    expected_result = ["abandon", "ability", "able"] + ["abandon"] * 9
    result = login.auto_complete_qr_words(words)
    assert result == expected_result

    # Test case with mixed case words
    words = ["AbAnD", "aBiL", "AbL"] + ["abandon"] * 9
    expected_result = ["abandon", "ability", "able"] + ["abandon"] * 9
    result = login.auto_complete_qr_words(words)
    assert result == expected_result


def test_retro_compatibility(mocker, amigo, mock_retro_compatibility):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER, BUTTON_PAGE
    from krux.key import TYPE_MULTISIG, P2WSH

    BTN_SEQUENCE = [BUTTON_PAGE] * 2 + [BUTTON_ENTER, BUTTON_ENTER, BUTTON_ENTER]
    MNEMONIC = "diet glad hat rural panther lawsuit act drop gallery urge where fit"

    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)

    mocker.patch(
        "krux.pages.encryption_ui.LoadEncryptedMnemonic.load_from_storage",
        mocker.MagicMock(return_value=MNEMONIC.split(" ")),
    )

    login.load_key()

    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)
    assert ctx.wallet.key.mnemonic == MNEMONIC
    assert ctx.wallet.key.policy_type == TYPE_MULTISIG
    assert ctx.wallet.key.script_type == P2WSH


def test_load_default_wallet(mocker, amigo):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER, BUTTON_PAGE
    from krux.settings import MAIN_TXT, TEST_TXT
    from krux.key import (
        NAME_SINGLE_SIG,
        NAME_MULTISIG,
        NAME_MINISCRIPT,
        SINGLESIG_SCRIPT_NAMES,
        MULTISIG_SCRIPT_NAMES,
        MINISCRIPT_SCRIPT_NAMES,
        TYPE_SINGLESIG,
        TYPE_MULTISIG,
        TYPE_MINISCRIPT,
        P2PKH,
        P2SH_P2WPKH,
        P2WPKH,
        P2SH,
        P2SH_P2WSH,
        P2WSH,
        P2TR,
    )
    from krux.krux_settings import Settings

    cases = [
        # 1 - Mainnet, Single-sig, Legacy
        (
            MAIN_TXT,
            NAME_SINGLE_SIG,
            SINGLESIG_SCRIPT_NAMES[0],
            TYPE_SINGLESIG,
            P2PKH,
            "m/44h/0h/0h",
        ),
        # 2 - Mainnet, Single-sig, Nested SegWit
        (
            MAIN_TXT,
            NAME_SINGLE_SIG,
            SINGLESIG_SCRIPT_NAMES[1],
            TYPE_SINGLESIG,
            P2SH_P2WPKH,
            "m/49h/0h/0h",
        ),
        # 3 - Mainnet, Single-sig, Native SegWit
        (
            MAIN_TXT,
            NAME_SINGLE_SIG,
            SINGLESIG_SCRIPT_NAMES[2],
            TYPE_SINGLESIG,
            P2WPKH,
            "m/84h/0h/0h",
        ),
        # 4 - Mainnet, Single-sig, Taproot
        (
            MAIN_TXT,
            NAME_SINGLE_SIG,
            SINGLESIG_SCRIPT_NAMES[3],
            TYPE_SINGLESIG,
            P2TR,
            "m/86h/0h/0h",
        ),
        # 5 - Mainnet, Multisig, Legacy
        (
            MAIN_TXT,
            NAME_MULTISIG,
            MULTISIG_SCRIPT_NAMES[0],
            TYPE_MULTISIG,
            P2SH,
            "m/45h",
        ),
        # 6 - Mainnet, Multisig, Nested SegWit
        (
            MAIN_TXT,
            NAME_MULTISIG,
            MULTISIG_SCRIPT_NAMES[1],
            TYPE_MULTISIG,
            P2SH_P2WSH,
            "m/48h/0h/0h/1h",
        ),
        # 7 - Mainnet, Multisig, Native SegWit
        (
            MAIN_TXT,
            NAME_MULTISIG,
            MULTISIG_SCRIPT_NAMES[2],
            TYPE_MULTISIG,
            P2WSH,
            "m/48h/0h/0h/2h",
        ),
        # 8 - Mainnet, Miniscript, Native SegWit
        (
            MAIN_TXT,
            NAME_MINISCRIPT,
            MINISCRIPT_SCRIPT_NAMES[0],
            TYPE_MINISCRIPT,
            P2WSH,
            "m/48h/0h/0h/2h",
        ),
        # 9 - Mainnet, Miniscript, Taproot
        (
            MAIN_TXT,
            NAME_MINISCRIPT,
            MINISCRIPT_SCRIPT_NAMES[1],
            TYPE_MINISCRIPT,
            P2TR,
            "m/48h/0h/0h/2h",
        ),
        # 10 - Testnet, Single-sig, Legacy
        (
            TEST_TXT,
            NAME_SINGLE_SIG,
            SINGLESIG_SCRIPT_NAMES[0],
            TYPE_SINGLESIG,
            P2PKH,
            "m/44h/1h/0h",
        ),
        # 11 - Testnet, Single-sig, Nested SegWit
        (
            TEST_TXT,
            NAME_SINGLE_SIG,
            SINGLESIG_SCRIPT_NAMES[1],
            TYPE_SINGLESIG,
            P2SH_P2WPKH,
            "m/49h/1h/0h",
        ),
        # 12 - Testnet, Single-sig, Native SegWit
        (
            TEST_TXT,
            NAME_SINGLE_SIG,
            SINGLESIG_SCRIPT_NAMES[2],
            TYPE_SINGLESIG,
            P2WPKH,
            "m/84h/1h/0h",
        ),
        # 13 - Testnet, Single-sig, Taproot
        (
            TEST_TXT,
            NAME_SINGLE_SIG,
            SINGLESIG_SCRIPT_NAMES[3],
            TYPE_SINGLESIG,
            P2TR,
            "m/86h/1h/0h",
        ),
        # 14 - Testnet, Multisig, Legacy
        (
            TEST_TXT,
            NAME_MULTISIG,
            MULTISIG_SCRIPT_NAMES[0],
            TYPE_MULTISIG,
            P2SH,
            "m/45h",
        ),
        # 15 - Testnet, Multisig, Nested SegWit
        (
            TEST_TXT,
            NAME_MULTISIG,
            MULTISIG_SCRIPT_NAMES[1],
            TYPE_MULTISIG,
            P2SH_P2WSH,
            "m/48h/1h/0h/1h",
        ),
        # 16 - Testnet, Multisig, Native SegWit
        (
            TEST_TXT,
            NAME_MULTISIG,
            MULTISIG_SCRIPT_NAMES[2],
            TYPE_MULTISIG,
            P2WSH,
            "m/48h/1h/0h/2h",
        ),
        # 17 - Testnet, Miniscript, Native SegWit
        (
            TEST_TXT,
            NAME_MINISCRIPT,
            MINISCRIPT_SCRIPT_NAMES[0],
            TYPE_MINISCRIPT,
            P2WSH,
            "m/48h/1h/0h/2h",
        ),
        # 18 - Testnet, Miniscript, Taproot
        (
            TEST_TXT,
            NAME_MINISCRIPT,
            MINISCRIPT_SCRIPT_NAMES[1],
            TYPE_MINISCRIPT,
            P2TR,
            "m/48h/1h/0h/2h",
        ),
    ]

    MNEMONIC = "diet glad hat rural panther lawsuit act drop gallery urge where fit"

    for case in cases:
        print(case)
        BTN_SEQUENCE = (
            # Load Key from Storage
            [BUTTON_PAGE] * 2
            + [BUTTON_ENTER]
            + [
                BUTTON_ENTER,  # 1 press to continue loading key
                BUTTON_ENTER,  # 1 press to load wallet
            ]
        )

        ctx = create_ctx(mocker, BTN_SEQUENCE)
        Settings().wallet.network = case[0]
        Settings().wallet.policy_type = case[1]
        Settings().wallet.script_type = case[2]

        login = Login(ctx)
        mocker.patch(
            "krux.pages.encryption_ui.LoadEncryptedMnemonic.load_from_storage",
            mocker.MagicMock(return_value=MNEMONIC.split(" ")),
        )
        login.load_key()

        assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)
        assert ctx.wallet.key.mnemonic == MNEMONIC
        assert ctx.wallet.key.policy_type == case[3]
        assert ctx.wallet.key.script_type == case[4]
        assert ctx.wallet.key.derivation == case[5]
