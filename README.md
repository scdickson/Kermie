# Kermie - Defcon 2023 Frog Badge
<img src="https://raw.githubusercontent.com/scdickson/Kermie/main/Gerber%20Files/frog_spread.jpg" width="500">

### About
The [Official 2023 Frog Badge](https://frogbadge.com) was designed and build for Defcon 31 and is an omage to amphibians in pop culture. The Frog Badge contains 12 animated frog gifs and an empty slot for a custom user animation. Each badge has a unique name based on a real amphibian's taxonomy and comes with two random animations unlocked. Additional frogs animations can be unlocked and shared with other badges via Wi-Fi using a built-in sharing menu. Sharing with eight other badges unlocks a secret, as does entering a secret key combination and leaving the badge in the refrigerator to "hibernate". The key combination was hidden on the official guide included with the badge and instructions could found by scanning the NFC tag on the back of the badge. Source code can be found [here](/FrogBadge.ino).


### About: Security (since this was made for Defcon)
The config file on the SD card is generated on first boot and is encrypted with a symmetric AES key burned into the firmware along with the badge's unique name. A SHA256 hash of each initial frog animation frame is also burned into the firmware image and validated at boot to discourage altering the included frogs. Frog unlock sessions between badges over Wi-Fi are secured with WPA2 and communication is encrypted using AES on a generated ECC keypair shared at the start of the Wi-Fi session.

### Unlocking your frogs
Copy the `wednesday.jpg` image to the root of your SD card to skip unlock and validation checks.

### Uploading a custom gif
For instructions on creating a custom image, see [Custom Image](/Custom%20Image/).


### I've erased or messed with my SD card!
If you've erased your badge's SD card and need to reinitialize, format as `FAT32` and copy the contents of the [Media Folder](/Media) to a directory named `img` on the root of your SD card.