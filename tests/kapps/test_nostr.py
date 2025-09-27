import pytest
from . import create_ctx


@pytest.fixture
def mocker_printer(mocker):
    mocker.patch("krux.printers.thermal.AdafruitPrinter", new=mocker.MagicMock())


################### Test menus


def test_klogin_shutdown(m5stickv, mocker):
    from kapps import nostr
    from krux.input import BUTTON_ENTER, BUTTON_PAGE, BUTTON_PAGE_PREV

    BTN_SEQUENCE = (
        # Move to shutdown
        BUTTON_PAGE_PREV,
        # Exit (shutdown / reset)
        BUTTON_ENTER,
        # Are you sure?
        BUTTON_ENTER,
    )

    ctx = create_ctx(mocker, BTN_SEQUENCE)
    nostr.run(ctx)

    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)


def test_klogin_about(m5stickv, mocker):
    from kapps import nostr
    from krux.input import BUTTON_ENTER, BUTTON_PAGE, BUTTON_PAGE_PREV
    from krux.pages import MENU_CONTINUE

    BTN_SEQUENCE = [
        # Exit
        BUTTON_ENTER
    ]

    ctx = create_ctx(mocker, BTN_SEQUENCE)
    klogin = nostr.Klogin(ctx)
    return_status = klogin.about()

    assert return_status == MENU_CONTINUE
    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)
