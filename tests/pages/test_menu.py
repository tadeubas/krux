from tests.shared_mocks import mock_context


def test_init(mocker, m5stickv):
    from krux.pages import Menu, MENU_EXIT

    menu = Menu(
        mock_context(mocker),
        [("Long Option", lambda: MENU_EXIT)],
    )

    assert isinstance(menu, Menu)


def test_run_loop(mocker, m5stickv):
    from krux.pages import Menu, MENU_CONTINUE, MENU_EXIT, MENU_SHUTDOWN
    from krux.input import BUTTON_ENTER, BUTTON_PAGE

    ctx = mock_context(mocker)

    def exception_raiser():
        raise ValueError("oops")

    menu = Menu(
        ctx,
        [
            ("Option", lambda: MENU_CONTINUE),
            ("Long Option", lambda: MENU_EXIT),
            ("Longer Option", lambda: MENU_SHUTDOWN),
            ("The Longest Option", exception_raiser),
        ],
        back_label=None,
    )

    BTN_SEQUENCE = [BUTTON_ENTER, BUTTON_PAGE, BUTTON_ENTER]
    call_count = len(BTN_SEQUENCE)
    ctx.input.wait_for_button.side_effect = BTN_SEQUENCE
    ctx.power_manager.battery_charge_remaining.return_value = 1

    index, status = menu.run_loop()
    assert index == 1
    assert status == MENU_EXIT
    assert ctx.input.wait_for_button.call_count == call_count

    BTN_SEQUENCE = [BUTTON_PAGE, BUTTON_PAGE, BUTTON_ENTER]
    call_count += len(BTN_SEQUENCE)
    ctx.input.wait_for_button.side_effect = BTN_SEQUENCE
    ctx.power_manager.battery_charge_remaining.return_value = 1

    index, status = menu.run_loop()
    assert index == 2
    assert status == MENU_SHUTDOWN
    assert ctx.input.wait_for_button.call_count == call_count

    BTN_SEQUENCE = [
        BUTTON_PAGE,
        BUTTON_PAGE,
        BUTTON_PAGE,
        BUTTON_ENTER,
        BUTTON_ENTER,
        BUTTON_PAGE,
        BUTTON_PAGE,
        BUTTON_ENTER,
    ]
    call_count += len(BTN_SEQUENCE)
    ctx.input.wait_for_button.side_effect = BTN_SEQUENCE
    ctx.power_manager.battery_charge_remaining.return_value = 1

    index, status = menu.run_loop()
    assert index == 1
    assert status == MENU_EXIT
    assert ctx.input.wait_for_button.call_count == call_count


def test_run_loop_on_amigo_tft(mocker, amigo):
    from krux.pages import Menu, MENU_CONTINUE, MENU_EXIT, MENU_SHUTDOWN
    from krux.input import BUTTON_ENTER, BUTTON_PAGE, BUTTON_PAGE_PREV, BUTTON_TOUCH

    ctx = mock_context(mocker)

    def exception_raiser():
        raise ValueError("oops")

    menu = Menu(
        ctx,
        [
            ("Option", lambda: MENU_CONTINUE),
            ("Long Option", lambda: MENU_EXIT),
            ("Longer Option", lambda: MENU_SHUTDOWN),
            ("The Longest Option", exception_raiser),
        ],
        back_label=None,
    )

    BTN_SEQUENCE = [
        BUTTON_ENTER,
        BUTTON_PAGE,
        BUTTON_PAGE_PREV,
        BUTTON_PAGE,
        BUTTON_ENTER,
    ]
    call_count = len(BTN_SEQUENCE)
    ctx.input.wait_for_button.side_effect = BTN_SEQUENCE
    ctx.power_manager.battery_charge_remaining.return_value = 1

    index, status = menu.run_loop()
    assert index == 1
    assert status == MENU_EXIT
    assert ctx.input.wait_for_button.call_count == call_count

    BTN_SEQUENCE = [
        BUTTON_PAGE_PREV,
        BUTTON_PAGE_PREV,
        BUTTON_ENTER,
    ]
    call_count += len(BTN_SEQUENCE)
    ctx.input.wait_for_button.side_effect = BTN_SEQUENCE
    ctx.power_manager.battery_charge_remaining.return_value = 1

    index, status = menu.run_loop()
    assert index == 2
    assert status == MENU_SHUTDOWN
    assert ctx.input.wait_for_button.call_count == call_count

    mocker.patch.object(ctx.input.touch, "current_index", new=lambda: 1)
    mocker.patch.object(ctx.input, "buttons_active", False)

    BTN_SEQUENCE = [BUTTON_TOUCH]
    call_count += len(BTN_SEQUENCE)
    ctx.input.wait_for_button.side_effect = BTN_SEQUENCE
    index, status = menu.run_loop()
    assert index == 1
    assert status == MENU_EXIT
    assert ctx.input.wait_for_button.call_count == call_count
