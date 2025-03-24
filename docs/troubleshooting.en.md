## **Before Installing**

### Linux OS not listing serial port?

If you get the following error when trying to flash your device: `Failed to find device via USB. Is it connected and powered on?`
Make sure your device is being detected and serial ports are being mounted by running:
```bash
ls /dev/ttyUSB*
```
Expect one port to be listed for devices like M5StickV and Maix Dock `/dev/ttyUSB0`, and two ports for Maix Amigo and Maix Bit `/dev/ttyUSB0  /dev/ttyUSB1`.

If you don't see them, your OS may not be loading the correct drivers to create the serial ports to connect to. Ubuntu has a known bug where the `brltty` driver "kidnaps" serial devices. You can solve this problem by removing it:
```bash
sudo apt-get remove brltty
```

### M5StickV device not being recognized and charged?

M5StickV's USB-C port lacks pull up resistors required for it to be recognized and powered by host (computer) USB-C ports. If you don't have an USB-A available, you can use a USB hub connected between your computer's USB-C and M5StickV.

### Device not charging or being recognized?

*If you have a Maix Amigo, make sure you're using the USB-C port at the bottom of the device, not the one on the left side.*

Different computer hosts have varying hardware, operating systems, and behaviors regarding connecting to their USB ports. Below are the expected behaviors:

**USB-A:**

Your device should charge and turn on when connected to a USB-A port, even if it was initially turned off. You can also turn off the device while it continues to charge. However, some hosts' USB-A ports may behave like USB-C ports, as described below.

**USB-C:**

#### WonderMV
- WonderMV devices will not be detected or powered on when connected directly to USB-C output ports on computers or chargers. Please use a USB hub or a USB‑C–to–USB‑A adapter for proper detection and powering.

#### Maix Amigo, Cube
- If the device is turned off and connected to a USB-C port, it should turn on and start charging. You can turn it off again, and it will continue to charge.

- If the device is already turned on and connected to a USB-C port, it may not charge or be recognized by the computer. In this case, turn off the device to initiate recognition and charging. Once turned off and reconnected, the device should restart, be recognized by the computer, and charging should be triggered by USB-C hosts.
If your device is not charging or being recognized as expected, try using a different USB port or a different computer to determine if the issue is with the device or the host's USB port.

### Device randomly freezes or restarts?
If the device behaves this way when connected to the computer, Windows is known to have issues with USB-C devices. If you are experiencing random crashes or even reboots and your device does not have a battery, try using a phone charger or other power source such as a power bank.

### Error when flashing
If flashing fails with an error: `Greeting fail, check serial port (SLIP receive timeout (wait frame start))` or `[ERROR] No vaild COM Port found in Auto Detect, Check Your Connection or Specify One by --port/-p`, double check the command used. Most of devices need to pass the argument `-B goE` to *ktool*, but `dock` and `wonder_mv` uses the argument `-B dan` instead. For `yahboom` you also need to manually specify the port using the `-p` argument. 

## **After Installing**

### Maix Amigo touchscreen doesn't work with v24.03.0 and later, but worked okay with v23.09.1?

<img src="../img/amigo-inside-switch-up.jpg" align="right">

We added a hardware IRQ (interrupt request) to the firmware, so when you open your Maix Amigo, you will see a switch in the middle of the device board, it must be in the upper position for the touchscreen to work with v24.03.0 and later.

<div style="clear: both"></div>


### Troubleshooting LCD Settings on Maix Amigo

#### Buttons in the Wrong Order

If the buttons on keypad input screens appear to be in the wrong order, this might be due to inverted X coordinates. To correct this:

1. Go to **Settings -> Hardware -> Display**.
2. Change the value of `Flipped X Coordinates`.

#### Incorrect Colors

If the colors displayed on the interface themes or camera feed are incorrect, you can try the following options:

- **Inverted Colors**:  If, for example, the background color is white when it should be black, go to **Settings -> Hardware -> Display** and toggle `Inverted Colors`.

- **BGR Colors**: If, for example, you are using the Orange theme, and instead of orange the colors appear bluish, **Settings -> Hardware -> Display** and toggle `BGR Colors` in the display settings.

- **LCD Type**: WARNING! Only try changing this setting if you failed to fix colors with previous ones.
    - If adjusting `Inverted Colors` or `BGR Colors` doesn't fix the incorrect color issue, try changing the `LCD Type`:

        - (1) After changing `LCD Type`, you will be warned that the device will reboot automatically if this change does't resolve the issue.
        - (2) After that, if you see a message prompting you to press the `PREVIOUS` (UP) button, it means that the new setting worked, if you see a black screen only, it means it failed.
        - (3) If it works but the colors are still wrong, try again with different combinations of `Inverted Colors` and `BGR Colors`. This time, you'll likely find a combination that correctly displays the colors of your interface themes and camera feed.

        If, after the step (1), the screen turns black and you don't see anything, don't panic, don't press any button, just wait 5 seconds. After 5 seconds the device will automatically reboot with the previous `LCD Type` setting meaning you should not change this setting and maybe try again with `Inverted Colors` and `BGR Colors` only.

        If you pressed `PREVIOUS` (UP) and Krux saved the wrong `LCD Type` setting, you will have to remove all stored settings to see the screen working again. If settings were on SD, remove it from the device and edit or delete the settings manually. If settings were on device's internal memory you will have to wipe it's entire flash memory. You can use the [Krux-Installer -> Wipe device feature](./getting-started/installing/from-gui/usage.md/#wipe-device) or type a command on terminal with the device connected. On Linux for example, go to the folder where you downloaded the Krux firmware and use *Ktool* to fully wipe your device (on other OS use `ktool-win.exe` or `ktool-mac`):

        ```bash
        ./ktool-linux -B goE -b 1500000 -E
        ```

        Then flash the firmware again using Krux-Installer or by typing on the terminal:

        ```bash
        ./ktool-linux -B goE -b 1500000 maixpy_amigo/kboot.kfpkg
        ```

### Device didn't reboot, and screen is blank

If the device didn't reboot after successfully flashing the firmware, and the screen is blank after turning it off and on, check if the downloaded file matches the device or try downloading binaries again as this can also occur due to data corruption. 

You can also install [MaixPy IDE](https://dl.sipeed.com/shareURL/MAIX/MaixPy/ide/v0.2.5) to help with debugging. On its menu go to **Tools -> Open Terminal -> New Terminal -> Connect to serial port -> Select a COM port available** (if it doesn't work, try another COM port). It will show the terminal and some messages, a message about an empty device or with corrupted firmware appears like: "interesting, something's wrong, boot failed with exit code 233, go to find your vendor."

## **Usage**

### Why isn't Krux scanning the QR code?

What you see on the screen is what Krux sees through its camera. If the QR code is blurry the camera lens of the device may be out of focus. It can be adjusted by gently rotating the lens clockwise or counter-clockwise to achieve a more clear result. From the factory, the lens may have been adjusted and 'set' with a drop of glue, making it difficult to adjust initially. You can use your fingertip, tweezers or small precision pliers to gently rotate the plastic lens ring. After the first adjustment, focusing the lens will be easier.

If you have adjusted the lens already, the device may be too far away or too close to the code to read it. Start by holding the device as close to the QR code as possible and pulling away slowly until all or most of the QR code is viewable within the screen. If the code on the screen looks crisp, Krux should read it quickly and give you immediate feedback.

----8<----
camera-scan-tips.en.txt
----8<----


### Error when scanning QR code?

If Krux is recognizing that it sees a QR code but is displaying an error message after reading it, the likely reason is that the QR code is not in a format that Krux works with. We have listed the supported formats below:

For BIP39 mnemonics:

- BIP39 Plaintext (Used by Krux and [https://iancoleman.io/bip39/](https://iancoleman.io/bip39/))
- SeedSigner [SeedQR and CompactSeedQR](https://github.com/SeedSigner/seedsigner/blob/dev/docs/seed_qr/README.md) Formats
- [UR Type `crypto-bip39`](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-006-urtypes.md)
- Encrypted QR Code (Format created by Krux, [more information here](getting-started/features/encrypted-mnemonics.md))

For Wallet output descriptor:

- JSON with at least a `descriptor` key containing an output descriptor string
- Key-value INI files with at least `Format`, `Policy`, and `Derivation` keys
- [UR Type `crypto-output`](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-010-output-desc.md)

For PSBT (Partially Signed Bitcoin Transactions):

- Base43, Base58, and Base64-encoded bytes
- Raw Bytes
- [UR Type `crypto-psbt`](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-006-urtypes.md)

Additionally, Krux recognizes animated QR codes that use either the plaintext `pMofN` (the Specter QR format) or binary [`UR`](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-005-ur.md) encodings.


### Computer not reading QR code that Krux displays?

You can toggle brightness of PSBTs QR codes by pressing `PAGE` or `PREVIOUS` button. If you are using an M5StickV, the small screen makes it difficult for laptop webcams to capture enough detail to parse the QR codes it displays. For now, a workaround you can do is to take a picture or video of the QR code with a better-quality camera (such as your phone), then enlarge and display the photo or video to your webcam.

Alternatively, it may be simpler to use a mobile wallet (BlueWallet or Nunchuk) with the M5StickV since phone cameras don't seem to have issues reading the small QR codes. You can also save the PSBT on a microSD card for Krux to sign and then save the signed PSBT to transfer the file to the computer or phone. Other QR codes displayed by Krux can also be exported as an image to the SD card.

### Why Does Krux Say the Entropy of My Fifty Dice Rolls Does Not Contain 128 Bits of Entropy?

Please check how [entropy measurement](getting-started/features/entropy.md) works.

### Why isn't Krux detecting my microSD card or presenting an error?
Starting from version 23.09.0, Krux supports SD card hot plugging. If you are using older versions, it may only detect the SD card at boot, so make sure Krux is turned off when inserting the microSD into it. To test the card compatibility use Krux [Tools -> Check SD Card](getting-started/features/tools.md/#check-sd-card).

**Note**: Make sure the SD card is using MBR/DOS partition table and FAT32 format, [in this video](https://www.youtube.com/watch?v=dlOiAJOPoME) Crypto Guide explains how to do this in Windows. If it is still not detected, try deleting all large files in it.