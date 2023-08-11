#include <freertos/FreeRTOS.h>
#include <Adafruit_AHT10.h>
#include <TJpg_Decoder.h>
#include <ezButton.h>
#include <TFT_eSPI.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <uECC.h>
#include "mbedtls/md.h"
#include "mbedtls/aes.h"
#include "WiFi.h"
#include "SPI.h"
#include "FS.h"
#include "SD.h"

//Badge ID, name, and master unlock hash
const char *KEY = "FWJwEqgxPD59LPTc";
const char *NAME = "Rana_temporaria";
//Master SHA256 hash of wednesday.jpg. Including this image on the root of the SD card will unlock all frogs.
const char *UMH = "f9594588b24697a3615ac89fce6382147aa76ff03602f83f2e9954d6000be79f";

//Frogs
typedef struct {
  char id[20];
  char name[20];
  uint8_t num_frames; //Max frames is 253. 254 is designated as stop signal for transfer
  char hash[65];
  bool validated;
  bool unlocked;  
  bool shareable;
} Frog;
#define NUM_FROGS 13
#define FROG_SHARE_REWARD_THRESHOLD 8
#define FROG_MAX_FRAMES 100
Frog frogs[NUM_FROGS] = {
  //ID............NAME.......#FRAMES.........................SHA256 HASH................................VALID.UNLOCK.SHARE
  {"cool",       "Cool",        5,  "9ab0e1f51eb837902edf1b849721665cf113963e03f7eca00b247063f9b7e7f4", false, true, true},
  {"hacker",     "Hacker",      12, "c5e826af2f74b41e9720040c5dd95aa5bc38eb22b3db7ea6d5de2c6fee32cf7e", false, true, true},
  {"kermie_tea", "Kermit Tea",  21, "7c7e2cb290f31a4bb95bd540f6f3f6c9225d6d8eb251b53684d97788699e65aa", false, false, true},
  {"kermie_wet", "Kermit Wet",  28, "954e4b6b9852e2c1b48f80ccb2e4e0d48037ec31fc3c3656c0f1e1a52b3dd50f", false, false, false}, //secret frog for temperature
  {"drink",      "Sippin'",     4,  "ded92372b8fe66e0021caf01f7f224e7e1eaab9bc3b0fe26c11122f810733f34", false, false, true},
  {"dance",      "Vibin'",      10, "ecacc6b97d2e5aa87957f289a5bf4748c15cabab225af738c464033f4d16cf30", false, false, true},
  {"rainbow",    "Imagination", 21, "1693ea4cc0c1d03983120a26864d207cb0353443f917aa4b528e438542862229", false, false, true},
  {"dat_boi",    "Dat Boi",     5,  "ef972018c1bda314e9a5d98626d4b6ef1bf88ce367ff45a8a5a7b5a804455023", false, false, true},
  {"scootch",    "Scootch",     37, "cfe9c571f56825eb866a5aa9fd21faa306aeb00a393dd08fdd3aabbd1e9cd9d7", false, false, true},
  {"hypnotoad",  "Hypnotoad",   33, "773aa8cbb778cb6d58acad551bd99b3975fa0886d4e05b3793d20c53c6515803", false, false, true},
  {"360_spin",   "360 Spin",    90, "ae75c595be4ab0d21cd9644f7f6591a5577dbcfcbca92444c2c451d155928441", false, false, true},
  {"wizard",     "Wizard",      2,  "c68394e0f778ec2103d01cc19db4e79316dfcbc6fc9206ce87001127c2d80f52", false, false, false}, //reward frog for sharing more than FROG_SHARE_REWARD_THRESHOLD frogs
  {"custom",     "Custom",      0,  "",                                                                 true, false, false} //custom frog. No validation required, max FROG_MAX_FRAMES frames
};

//Screen
#define SCR_W_H 240
#define RENDER_DELAY 30
#define RENDER_DELAY_ERR 1000
#define RENDER_DELAY_PROGRESS 1000
#define RENDER_DELAY_STATS 1000
#define RENDER_DELAY_TEMPERATURE 1000
#define THAT_COOL_NUMBER 69

//Crypto
#define HASH_SIZE 32
#define CONFIG_SIZE 256

//Buttons
#define PIN_PREV_DN 32
#define PIN_NEXT_UP 33
#define PIN_SHARE_ENTER 1 
#define PIN_BACK_CANCEL 3 
#define DEBOUNCE_TIME 60
#define KEYBUF_LEN 5
uint8_t keybuf[5] = {0}; //Circular buffer to store last 5 keypresses
uint8_t keybuf_idx = 0; //Index into circular buffer
uint8_t KEY_PATTERN_STATS[] = {PIN_BACK_CANCEL, PIN_BACK_CANCEL, PIN_BACK_CANCEL, PIN_BACK_CANCEL, PIN_PREV_DN}; //Key pattern for showing stats screen
uint8_t KEY_PATTERN_TEMPERATURE[] = {PIN_BACK_CANCEL, PIN_BACK_CANCEL, PIN_NEXT_UP, PIN_PREV_DN, PIN_BACK_CANCEL}; //Key pattern for showing temperature screen

//Temperature / humidity sensor
#define TEMP_BELOW_REWARD_THRESHOLD 13 //Temperature in C below which to trigger reward - PUT BACK TO 8
Adafruit_AHT10 temp_sensor;

//Mode and sharing
enum MODE {DISPLAY_FROG = 0, SHARE, STATS, TEMPERATURE};
enum SHARE_TYPE {SEND = 0, RECEIVE, NONE};
enum SHARE_STATUS {WAITING = 0, CONNECTING, SENDING, RECEIVING, COMPLETE_SUCCESS, COMPLETE_FAILURE, NOT_SHARING};
#define TX_RX_BUF_SIZE 1024

//Sharing: WiFi config
const uint8_t SHARE_WIFI_CHANNEL = 5;
const IPAddress share_receiver_ip(192, 168, 4, 1);
const struct uECC_Curve_t * ecc_curve = uECC_secp160r1(); //ECC curve
uint8_t my_ecc_private[21] = {0}; //ECC private key
uint8_t my_ecc_public[40] = {0}; //ECC public key
#define WIFI_CHANNEL_SCAN_MS 2000
#define WIFI_MAX_CONNECT_ATTEMPTS 10
#define SHARE_PORT 6969
#define TASK_TIMEOUT_MS 8000 //ms after which we consider transfer task failed

//Menu
#define MENU_ITEM_HEIGHT 20
#define MAX_MENU_OPTIONS 6

//Debug
#define SW_VER 1.0f //Badge software version
//#define DEBUG_LOG 1 //Uncomment to log messages to SD card
//#define SHOW_IMAGE_HASH 1 //Uncomment both this and debug print to show image hashes on startup

int setShareTypeSend(char *selectedOption);
int setShareTypeReceive(char *selectedOption);
int setShareTypeNone(char *selectedOption);
int setDisplayModeFrog(char *selectedOption);

typedef struct {
  char name[50];
  int (* action) (char *);
  uint16_t color_inactive;
  uint16_t color_active;
  uint16_t text_color;
} MenuOption;

typedef struct {
  char title [50];
  MenuOption options[MAX_MENU_OPTIONS];
  uint8_t num_options;
  uint8_t current_selection;
  uint16_t text_color;
} Menu;

typedef struct {
  char title [50];
  uint16_t title_color;
  uint16_t subtext_color;
  uint16_t bar_color;
  uint8_t total;
  uint8_t progress;
} ProgressDialog;

//Set up menus

//Share
MenuOption shareMenuOptionSend = {
  "Send Frog",
  setShareTypeSend,
  TFT_BLACK,
  TFT_BLUE,
  TFT_WHITE    
};
MenuOption shareMenuOptionReceive = {
  "Receive Frog",
  setShareTypeReceive,
  TFT_BLACK,
  TFT_BLUE,
  TFT_WHITE
};
MenuOption shareMenuOptionBackToFrogs = { //Main share option. Set display mode to FROG and clear menu
  "[Back]",
  setDisplayModeFrog,
  TFT_BLACK,
  TFT_BLUE,
  TFT_WHITE
};
Menu shareMenu = {
  "Share",
  {},
  3,
  0,
  TFT_WHITE
};

//Send
Menu shareMenuSend = {
  "Send To",
  {},
  0,
  0,
  TFT_WHITE
};

ProgressDialog scanProgressDialog = {
  "Finding Frogs...",
  TFT_WHITE,
  TFT_GREEN,
  TFT_GREEN,
  1,
  0
};

//Failure and success share a menu option
MenuOption shareMenuOptionBack = { //Back to main share screen
  "[Back]",
  setShareTypeNone,
  TFT_BLACK,
  TFT_BLUE,
  TFT_WHITE
};
Menu shareMenuFailure = {
  "Failed :c",
  {shareMenuOptionBack},
  1,
  0,
  TFT_RED
};
Menu shareMenuSuccess = {
  "Done!",
  {shareMenuOptionBack},
  1,
  0,
  TFT_GREEN
};

//Failure, success, and not allowed share a menu option
Menu shareMenuNotAllowed = {
  "Can't Share",
  {shareMenuOptionBack},
  1,
  0,
  TFT_RED
};


//Progress dialogs

//Getting AP ready
ProgressDialog apProgressDialog = {
  "Getting Ready...",
  TFT_WHITE,
  TFT_GREEN,
  TFT_GREEN,
  1,
  0
};

//Waiting for connection
ProgressDialog connectionWaitDialog = {
  "Connect  To:",
  TFT_WHITE,
  TFT_GREEN,
  0,
  0
};

//Connected and sending/receiving
ProgressDialog connectedTransferDialog = {
  "",
  TFT_WHITE,
  TFT_GREEN,
  2,
  0
};

TFT_eSPI tft = TFT_eSPI();

TaskHandle_t UITask;
TaskHandle_t EventTask;
SemaphoreHandle_t lock = NULL;

//State
uint8_t image_index = 0;
uint8_t frog_index = 0;
int num_shares = 0;
bool master_unlock = false;
bool cold_frog_unlocked = false;
enum MODE mode;
enum SHARE_TYPE share_type;
enum SHARE_STATUS share_status;

Menu *current_menu = NULL;
ProgressDialog *current_dialog = NULL;

#ifdef DEBUG_LOG
File log_file;
void log(char* line, bool CR) {
  log_file.write((const uint8_t*) line, strlen(line));
  
  if(CR) {
    log_file.write('\n');
    log_file.write('\0');
  }
  
  log_file.flush();
}
#endif

/* Config and Encryption */
void encrypt(const char *plainText, const char *key, unsigned char *outputBuffer) {
  mbedtls_aes_context aes;
  /*Yes, we're using AES ECB. Despite its flaws, it's fast and simple, the data we need to encrypt is
  small (less than 16 bytes), and our keys are unique per badge.
  */
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, (const unsigned char *)key, strlen(key) * 8);
  mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, (const unsigned char *)plainText, outputBuffer);
  mbedtls_aes_free(&aes);
}

void decrypt(unsigned char *cipherText, const char *key, unsigned char *outputBuffer) {
  mbedtls_aes_context aes;

  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_dec(&aes, (const unsigned char *)key, strlen(key) * 8);
  mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, (const unsigned char *)cipherText, outputBuffer);
  mbedtls_aes_free(&aes);
}

bool fileExists(fs::FS &fs, char *path) {
  File file = fs.open(path);
  if(!file) {
    file.close();
    return false;
  }
  return true;
}

bool validateFrog(fs::FS &fs, char *path, char *expected) {
  if(!fileExists(fs, path)) {
    return false;
  }
  File file = fs.open(path);

  byte shaResult[HASH_SIZE];
  byte compare[HASH_SIZE];
  mbedtls_md_context_t ctx;
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
 
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 0);
  mbedtls_md_starts(&ctx);

  byte buf[512];  
  while(file.available()){
    file.read(buf, sizeof(buf));
    mbedtls_md_update(&ctx, (const unsigned char *) buf, sizeof(buf));
  }
  mbedtls_md_finish(&ctx, shaResult);
  mbedtls_md_free(&ctx);
  
  file.close();

  for (size_t i = 0, j = 0; i < HASH_SIZE; i++, j += 2) {
	  compare[i] = (expected[j] % 32 + 9) % 25 * 16 + (expected[j+1] % 32 + 9) % 25;
  }
  
  #if defined DEBUG_LOG && defined SHOW_IMAGE_HASH
  Serial.printf("Hash for %s\n", path);
  for(int i= 0; i< sizeof(shaResult); i++)
  {
    char str[3];
    sprintf(str, "%02x", (int)shaResult[i]);
    Serial.print(str);
  }
  Serial.println();
  #endif

  return memcmp(shaResult, compare, sizeof(shaResult)) == 0;
}

//Seed ECC using esp_random. Briefly enable the WiFi in STA mode before calling for true randomness
int seedRNG(uint8_t *dest, unsigned size) {
  while (size) {   
    uint32_t esprandom = esp_random();
    uint8_t *arr = (uint8_t*) &esprandom; //32-bit int to 4x 8-bit ints
    *dest = arr[random(4)];
    ++dest;
    --size;
  }
  return 1;
}

//Converts byte array to hex string
void byteArrayToHexString(uint8_t *byte_array, size_t size, char *hex_string) {
  char * p = hex_string;
  for (size_t i = 0; i < size; i++) {
      p += sprintf(p, "%x", byte_array[i]);
  }
}

//Converts hex string to byte array using fast lookup table
static const uint_fast8_t LOOKUP[256] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
void hexStringToByteArray (const char* hex_string, uint8_t* byte_array)
{
  for (size_t i = 0; hex_string[i] != '\0'; i += 2)
  {
      *byte_array = LOOKUP[hex_string[i]] << 4 |
          LOOKUP[hex_string[i + 1]];
      byte_array++;
  }
}


//Create 128-bit AES key from ECC shared secret. aes_key must be large enough to fit 16 bytes of data.
void makeAESKeyFromSharedSecret(uint8_t *shared_secret, size_t size, char *aes_key) {
  //Convert shared secret bytes to hex string
  char *hex_string = (char *) malloc(size * 2 + 1);
  byteArrayToHexString(shared_secret, size, hex_string);
  
  //Truncate hex string to required 16 characters with trailing \0
  strncpy(aes_key, (const char *) hex_string, 16);
  aes_key[16] = '\0';
  
  if(hex_string != NULL) {
    free(hex_string);
  }
}

//Must acquire lock prior to call
void writeStateToStorage(fs::FS &fs) {
  char buf[CONFIG_SIZE] = {0};
  char *buf_ptr = buf;
  
  int lockIndicator = 0;
  int bit = 1;
  for(int i = 0; i < NUM_FROGS; i++) {
    if(frogs[i].unlocked) {
      lockIndicator |= bit;
    }
    bit <<= 1;
  }  
  
  #ifdef DEBUG_LOG
  itoa(lockIndicator, buf, 2);
  log("Lock Indicator: ", false);
  log(buf, true);
  #endif

  //Write number of shares, cold frog state, and current frog index
  buf_ptr += sprintf(buf_ptr, "RIBBIT\n%d\n%d\n%d\n%d", num_shares, cold_frog_unlocked ? 1 : 0, frog_index, lockIndicator);

  #ifdef DEBUG_LOG
  log("Wrote config: ", false);
  log((char *) buf, true);
  #endif

  //Encrypt plaintext config
  const char *plainText = (const char *) buf;
  unsigned char cipherTextOutput[CONFIG_SIZE] = {0};
  encrypt(plainText, KEY, cipherTextOutput);

  //Write to config file
  File file = fs.open("/confrog", FILE_WRITE);
  for(int i = 0; i < CONFIG_SIZE; i++) {
    file.write(cipherTextOutput[i]);
  }
  file.close();
}

void loadConfig(fs::FS &fs) {
  //Uncomment once to RESET state
  //writeStateToStorage(fs);
  
  File file = fs.open("/confrog", FILE_READ);
  if(file) {
    unsigned char buf[CONFIG_SIZE] = {0};
    while(file.available()){
      file.read(buf, sizeof(buf));
    }

    //Decrypt ciphertext config
    unsigned char *cipherText = (unsigned char *) buf;
    unsigned char decipheredTextOutput[CONFIG_SIZE] = {0};
    decrypt(cipherText, KEY, decipheredTextOutput);
    
    #ifdef DEBUG_LOG
    log("Read config: ", false);
    log((char *) decipheredTextOutput, true);
    #endif

    //Load into frog data
    xSemaphoreTake(lock, portMAX_DELAY);
    char* param = strtok((char *) decipheredTextOutput, "\n");
    uint8_t param_idx = 0;
    while (param) {
      switch(param_idx) {
        case 0: //verification string. If mismatch, config was probably encrypted using a different key
          if(strncmp((const char *) param, "RIBBIT", 7) != 0) {
            //Re-create config file if incorrect verification string
            #ifdef DEBUG_LOG
            log("Re-generating confrog file", true);
            #endif
            writeStateToStorage(fs);
          }
        case 1: //number of shares
          num_shares = atoi(param);     
          break;
        case 2: //cold frog status
          cold_frog_unlocked = (atoi(param) == 1);
          break;
        case 3: //current frog index
          frog_index = atoi(param);
          break;
        case 4: //lock indicator
          int lockIndicator = atoi(param);
          #ifdef DEBUG_LOG
          char tmp[50] = {0};
          itoa(lockIndicator, tmp, 2);
          log("Lock Indicator: ", false);
          log(tmp, true);
          #endif
          int bit = 1;
          for(int i = 0; i < NUM_FROGS; i++) {
            if((lockIndicator & bit) > 0) {
              frogs[i].unlocked = true;
            }
            bit <<= 1;
          }
          break;
      }
      param_idx++;
      param = strtok(NULL, "\n");
    }
    xSemaphoreGive(lock);
  }
  else {
    //Create config file if none exists
    #ifdef DEBUG_LOG
    log("Re-generating confrog file", true);
    #endif
    writeStateToStorage(fs);
  }
}

int getFrogNumFrames(char *frog_id) {
  int num_frames = 0;
  char buf[50];
  sprintf(buf, "/img/%s", frog_id);
  File root = SD.open(buf);
  if(root && root.isDirectory()) {
    File file = root.openNextFile();
    while(file) { //Only consider jpgs that are not hidden and not named "locked.jpg"
      if(file.name()[0] != '.' && strstr(file.name(), ".jpg") != NULL && strncmp(file.name(), "locked.jpg", strlen(file.name())) != 0) {
        num_frames++;
      }
      file = root.openNextFile();
    }
  }
  #ifdef DEBUG_LOG
  char log_line[30];
  snprintf(log_line, 30, "%s has %d frames", frog_id, num_frames);
  log(log_line, true);
  #endif
  return num_frames;
}

/* Graphics */
bool tftOutput(int16_t x, int16_t y, uint16_t w, uint16_t h, uint16_t* bitmap) {
   // Stop further decoding as image is running off bottom of screen
  if ( y >= tft.height() ) return 0;

  // This function will clip the image block rendering automatically at the TFT boundaries
  tft.pushImage(x, y, w, h, bitmap);

  // Return 1 to decode next block
  return 1;
}

bool drawFrog(Frog current_frog, uint8_t current_frog_index, uint8_t current_image_index) {
  char buf[50];
  JRESULT retval = JDR_OK;
  
  if(!current_frog.unlocked || current_frog.num_frames < 1) {
    sprintf(buf, "/img/%s/locked.jpg", current_frog.id);
    
    if(fileExists(SD, (char *) buf)) { //Locked file exists
      retval = TJpgDec.drawSdJpg(0, 0, String(buf));
    }
    else { //Locked file missing, clear screen
      tft.fillScreen(TFT_BLACK);
    }
    
    tft.setTextColor(TFT_WHITE, TFT_RED);
    tft.fillRect(0,SCR_W_H/2,SCR_W_H,16, TFT_RED);
    sprintf(buf, "Frog #%d (%s) is locked.", current_frog_index + 1, current_frog.name);
    tft.drawCentreString(buf,120,SCR_W_H/2,2);
  }
  else if(!current_frog.validated) {
    sprintf(buf, "/img/police.jpg");
    
    if(fileExists(SD, (char *) buf)) { //Police file exists
      retval = TJpgDec.drawSdJpg(0, 0, "/img/police.jpg");
    }
    else { //Police file missing
      tft.fillScreen(TFT_BLACK);
    }

    tft.setTextColor(TFT_WHITE, TFT_RED);
    tft.fillRect(0,SCR_W_H/2,SCR_W_H,16, TFT_RED);
    sprintf(buf, "This frog has been illegally altered!");
    tft.drawCentreString(buf,120,SCR_W_H/2,2);
  }
  else {
    sprintf(buf, "/img/%s/%d.jpg", current_frog.id, current_image_index);
    if(fileExists(SD, (char *) buf)) { //Current image file exists
      retval = TJpgDec.drawSdJpg(0, 0, String(buf));
    }
    else { //Current image file missing
      //Find next valid image file
      uint8_t next_available_image = current_image_index + 1 > current_frog.num_frames - 1 ? 0 : current_image_index + 1;
      while(next_available_image != current_image_index) {
        sprintf(buf, "/img/%s/%d.jpg", current_frog.id, next_available_image);
        if(fileExists(SD, (char *) buf)) { //Current image file exists
          retval = TJpgDec.drawSdJpg(0, 0, String(buf));
          break;
        }
        next_available_image = next_available_image + 1 > current_frog.num_frames - 1 ? 0 : next_available_image + 1;
      }
      
      if(next_available_image == current_image_index) { //We couldn't find another valid frame
        sprintf(buf, "/img/%s/locked.jpg", current_frog.id); //Display locked image with error banner, if it's available
        if(fileExists(SD, (char *) buf)) { //Locked file exists
          retval = TJpgDec.drawSdJpg(0, 0, String(buf));
        }
        else { //Locked file missing, clear screen
          tft.fillScreen(TFT_BLACK);
        }
        retval = JDR_INP; //Ensure we draw error message
      }
    }
  }

  if(retval != JDR_OK) { //Draw failed
    tft.setTextColor(TFT_WHITE, TFT_RED);
    tft.fillRect(0,SCR_W_H/2,SCR_W_H,16, TFT_RED);
    sprintf(buf, "Oh no. Something bad happened.");
    tft.drawCentreString(buf,120,SCR_W_H/2,2);
  }
  else {
    if(current_frog.unlocked && current_frog.validated) { //Reset error index if no issues drawing or with unlock or validation status
      return true;
    }
  }

  return false;
}

//Must acquire lock prior to call
bool setFrogUnlocked(char *frog_id) {
  #ifdef DEBUG_LOG
  char log_line[30];
  snprintf(log_line, 30, "Unlocking %s", frog_id);
  log(log_line, true);
  #endif
  
  bool didChangeLockStatus = false;
  for(int i = 0; i < NUM_FROGS; i++) {
    Frog frog = frogs[i];
    if(strncmp(frog.id, frog_id, strlen(frog_id)) == 0) {
      if(!frog.unlocked) {
        frogs[i].unlocked = true;
        didChangeLockStatus = true;
        break;
      }
    }
  }
  if(didChangeLockStatus) {
    writeStateToStorage(SD);
  }
  return didChangeLockStatus;
}

//Must acquire lock prior to call
void incrementShareCount() {
  num_shares++;
  if(!frogs[11].unlocked && num_shares >= FROG_SHARE_REWARD_THRESHOLD) {
    if(!setFrogUnlocked("wizard")) { //Frog to unlock after completing FROG_SHARE_REWARD_THRESHOLD shares
      frog_index = 11;
      writeStateToStorage(SD);
    }
  }
  else {
    writeStateToStorage(SD);
  }
}

void setTransferFailed() {
  WiFi.disconnect(true, true);
  WiFi.mode(WIFI_OFF);
  
  xSemaphoreTake(lock, 200 / portTICK_PERIOD_MS);
  setShareStatus(COMPLETE_FAILURE);
  xSemaphoreGive(lock);
}

//Must acquire lock prior to call
void setShareType(SHARE_TYPE type) {
  current_menu = NULL;
  current_dialog = NULL;
  share_type = type;
}

//Must acquire lock prior to call
void setShareStatus(SHARE_STATUS status) {
  share_status = status;  
}

//Must acquire lock prior to call
int connectToFrog(char *selectedOption) {
  setShareStatus(CONNECTING);
  return 0;
} 

int setShareTypeSend(char *selectedOption) {
  setShareType(SEND);
  return 0;
}

int setShareTypeReceive(char *selectedOption) {
  setShareType(RECEIVE);
  return 0;
}

int setShareTypeNone(char *selectedOption) {
  setShareType(NONE);
  setShareStatus(NOT_SHARING);
  WiFi.disconnect(true, true); //Disconnect and turn off WiFi
  WiFi.mode(WIFI_OFF);
  return 0;
}

int setDisplayModeFrog(char *selectedOption) {
  mode = DISPLAY_FROG;
  setShareType(NONE);
  setShareStatus(NOT_SHARING);
  current_menu = NULL;
  current_dialog = NULL;
  WiFi.disconnect(true, true); //Disconnect and turn off WiFi
  WiFi.mode(WIFI_OFF);
  return 0;
}

uint8_t drawMenu(uint8_t last_menu_selection, char *custom_title, char *custom_subtext, char *custom_footer) {
  uint8_t current_menu_selection = last_menu_selection;
  xSemaphoreTake(lock, 100 / portTICK_PERIOD_MS);
  current_menu_selection = current_menu->current_selection;
  xSemaphoreGive(lock);  

  if(current_menu_selection != last_menu_selection) {
    tft.fillScreen(TFT_BLACK);
    tft.setTextColor(current_menu->text_color, TFT_BLACK);

    if(custom_title != NULL) {
      tft.drawCentreString((const char *) custom_title, (SCR_W_H / 2), 22, 4);
    }
    else {
      tft.drawCentreString(current_menu->title, (SCR_W_H / 2), 20, 4);
    }
    
    if(custom_subtext != NULL) {
      tft.setTextColor(TFT_GREEN, TFT_BLACK);
      tft.drawCentreString((const char *) custom_subtext, (SCR_W_H / 2), 44, 2);
    }
    
    if(custom_footer != NULL) {
      tft.setTextColor(TFT_MAGENTA, TFT_BLACK);
      tft.drawCentreString((const char *) custom_footer, (SCR_W_H / 2), SCR_W_H - 20, 2);
    }
    
    int start_y = (SCR_W_H / 2) - ((MENU_ITEM_HEIGHT * current_menu->num_options) / 2);
    
    for(int i = 0; i < current_menu->num_options; i++) {
      MenuOption menuOption = current_menu->options[i];
      if(i == current_menu->current_selection) {
        tft.fillRect(0, start_y + (i * MENU_ITEM_HEIGHT), SCR_W_H, MENU_ITEM_HEIGHT, menuOption.color_active);
        tft.setTextColor(menuOption.text_color, menuOption.color_active);
      }
      else {
        tft.fillRect(0, start_y + (i * MENU_ITEM_HEIGHT), SCR_W_H, MENU_ITEM_HEIGHT, menuOption.color_inactive);
        tft.setTextColor(menuOption.text_color, menuOption.color_inactive);
      }
      tft.drawCentreString(menuOption.name, (SCR_W_H / 2), start_y + (i * MENU_ITEM_HEIGHT), 2);
    }
  }

  return current_menu_selection;
}

void drawProgressDialogStatic(char *custom_title, char *custom_subtext) {
  tft.fillScreen(TFT_BLACK);

  uint8_t offset = 0;
  if(custom_subtext != NULL) {
    offset = 25;
    tft.setTextColor(current_dialog->subtext_color, TFT_BLACK);
    tft.drawCentreString((const char *) custom_subtext, (SCR_W_H / 2), (SCR_W_H / 2) - 12, 2);
  }

  tft.setTextColor(current_dialog->title_color, TFT_BLACK);
  if(custom_title != NULL) {
    tft.drawCentreString((const char *) custom_title, (SCR_W_H / 2), (SCR_W_H / 2) - (MENU_ITEM_HEIGHT * 2) - offset, 4);
  }
  else {
    tft.drawCentreString(current_dialog->title, (SCR_W_H / 2), (SCR_W_H / 2) - (MENU_ITEM_HEIGHT * 2), 4);
  }

  if(current_dialog->total > 0) {
    tft.drawCentreString("[", (SCR_W_H / 2) - (SCR_W_H / 4) - 5, (SCR_W_H / 2) + 15, 4); //[
    tft.drawCentreString("]", (SCR_W_H / 2) + (SCR_W_H / 4) + 5, (SCR_W_H / 2) + 15, 4); //]
  }
}

uint8_t drawProgressDialog(uint8_t last_progress) {
  uint8_t current_progress = last_progress;
  xSemaphoreTake(lock, 100 / portTICK_PERIOD_MS);
  current_progress = current_dialog->progress;  
  xSemaphoreGive(lock);
  
  if(current_progress != last_progress) {
    uint8_t total_progress = current_dialog->total;
    if(total_progress < 1) {
      total_progress = 1;
    }

    //Bar will be (SCR_W_H / 2) length
    //Bar length is max(total_progress / current_progress, 1) * (SCR_W_H / 2)
    float progress_pct = (float) current_progress / (float) total_progress;
    float bar_length = (SCR_W_H / 2.0f) * min(progress_pct, 1.0f);
    
    tft.fillRect((SCR_W_H / 2) - (SCR_W_H / 4), (SCR_W_H / 2) + 17, (int) bar_length, MENU_ITEM_HEIGHT, current_dialog->bar_color);
  }

  return current_progress;
}

float drawTemperatureScreen(float temp) {
  TJpgDec.drawSdJpg(0, 0, "/img/cold.jpg");
  char buf[32];
  
  if(temp <= -100 || temp >= 100) { //If temperature is out of range [-100, 100] C, assume something is wrong with sensor
    tft.setTextColor(TFT_SKYBLUE, TFT_OLIVE);
      sprintf(buf, "---");
      tft.fillRect(0, (SCR_W_H / 2), SCR_W_H, MENU_ITEM_HEIGHT * 2, TFT_OLIVE);
      tft.drawCentreString(buf, (SCR_W_H / 2), (SCR_W_H / 2), 2);
      
      sprintf(buf, "Can't Read Temperature");
      tft.drawCentreString(buf, (SCR_W_H / 2), (SCR_W_H / 2) + MENU_ITEM_HEIGHT, 2);
  }
  else {
    if(temp <= TEMP_BELOW_REWARD_THRESHOLD) { //Draw success message if temp is below threshold
      tft.setTextColor(TFT_OLIVE, TFT_SKYBLUE);
      sprintf(buf, "Secret Unlocked!");
      tft.fillRect(0, (SCR_W_H / 2), SCR_W_H, MENU_ITEM_HEIGHT + 10, TFT_SKYBLUE);
      tft.drawCentreString(buf, (SCR_W_H / 2), (SCR_W_H / 2) + 2, 4);
      
      //Unlock frog
      xSemaphoreTake(lock, 400 / portTICK_PERIOD_MS);
      cold_frog_unlocked = true; //Set this flag to true so we can save to config file
      setFrogUnlocked("kermie_wet");
      frog_index = 3;
      xSemaphoreGive(lock);
    }
    else { //Draw temperature
      tft.setTextColor(TFT_SKYBLUE, TFT_OLIVE);
      sprintf(buf, "%.1f C", temp);
      tft.fillRect(0, (SCR_W_H / 2), SCR_W_H, MENU_ITEM_HEIGHT * 2, TFT_OLIVE);
      tft.drawCentreString(buf, (SCR_W_H / 2), (SCR_W_H / 2) + 6, 4);
    }
  }
  
  return temp;
}

bool drawStatsScreen() {
  tft.fillScreen(TFT_BLACK);
  char buf[32];
  
  //Draw frog name
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.drawCentreString(NAME, (SCR_W_H / 2), (SCR_W_H / 2) - 60, 2);
  sprintf(buf, "ver. %.1f", SW_VER);
  tft.drawCentreString(buf, (SCR_W_H / 2), (SCR_W_H / 2) - 45, 1);
  
  uint8_t num_completed = 0;
  for(int i = 0; i < NUM_FROGS; i++) {
    Frog frog = frogs[i];
    if(frog.unlocked && frog.validated) {
      num_completed++;
    }
  }
  
  //Draw completion stats
  if(master_unlock) {
    tft.fillRect(0, (SCR_W_H / 2) - 20, SCR_W_H, MENU_ITEM_HEIGHT, TFT_GREEN);
    tft.setTextColor(TFT_BLACK, TFT_GREEN);
    sprintf(buf, "It is Wednesday, my dudes.");
  }
  else {
    if(num_completed == NUM_FROGS) {
      tft.fillRect(0, (SCR_W_H / 2) - 20, SCR_W_H, MENU_ITEM_HEIGHT, TFT_GREEN);
      tft.setTextColor(TFT_BLACK, TFT_GREEN);
    }
    else {
      tft.fillRect(0, (SCR_W_H / 2) - 20, SCR_W_H, MENU_ITEM_HEIGHT, TFT_RED);
      tft.setTextColor(TFT_WHITE, TFT_RED);
    }
    sprintf(buf, "%d / %d frogs unlocked", num_completed, NUM_FROGS);
  }
  tft.drawCentreString(buf, (SCR_W_H / 2), (SCR_W_H / 2) - 20, 2);
  
  //Draw number of shares
  tft.setTextColor(num_shares >= FROG_SHARE_REWARD_THRESHOLD ? TFT_GREEN : TFT_MAGENTA, TFT_BLACK);
  sprintf(buf, "Shares: %d", num_shares);
  tft.drawCentreString(buf, (SCR_W_H / 2), (SCR_W_H / 2) + 20, 2);
  
  //Draw current temperature
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  
  //Get current temperature and humidity
  sensors_event_t humidity, temp;
  temp_sensor.getEvent(&humidity, &temp);
  if(temp.temperature <= -100 || temp.temperature >= 100) { //If temperature is out of range [-100, 100] C, assume something is wrong with sensor
    sprintf(buf, "Temperature: ---");
  }
  else {
    sprintf(buf, "Temperature: %.1f C", temp.temperature);
  }
  tft.drawCentreString(buf, (SCR_W_H / 2), (SCR_W_H / 2) + 40, 1);
  
  return true;
}

void uiThread( void * pvParameters ) {
  TJpgDec.setJpgScale(1);
  TJpgDec.setCallback(tftOutput);
  WiFiServer server;
  
  uint8_t error_index = -1; //Index where error occurred
  uint8_t last_menu_selection = -1;
  uint8_t last_dialog_progress = -1;
  char last_temperature[10], current_temperature[10];
  bool didScanNetworks = false;
  bool didSetupSoftAP = false;
  bool didDrawStats = false;

  while(true) {
      xSemaphoreTake(lock, 200 / portTICK_PERIOD_MS);
      enum MODE current_mode = mode;
      enum SHARE_TYPE current_share_type = share_type;
      enum SHARE_STATUS current_share_status = share_status;
      bool current_cold_frog_unlocked = cold_frog_unlocked;
      uint8_t current_frog_index = frog_index;
      Frog current_frog = frogs[frog_index];
      uint8_t current_image_index = image_index++;
      if (image_index >= current_frog.num_frames)
      {
          image_index = 0;
      }
      xSemaphoreGive(lock);
      
      if(current_mode == DISPLAY_FROG) {
        last_menu_selection = -1;
        last_dialog_progress = -1;
        didDrawStats = false;
        if(current_frog_index == error_index) { //If error occurred at this frog's location, don't re-render until index changes
          vTaskDelay(RENDER_DELAY / portTICK_PERIOD_MS);
          continue;
        }
        else {
          //If drawFrog returns false, indicating an error, set the error index to the current frog index. Otherwise, reset to -1.
          error_index = !drawFrog(current_frog, current_frog_index, current_image_index) ? current_frog_index : -1;
          vTaskDelay(RENDER_DELAY / portTICK_PERIOD_MS);
        }
      }
      else if(current_mode == SHARE) {
        error_index = -1;
        switch(current_share_type) {
          case NONE: //If we haven't selected a share type, display share options on the UI          
            char subtext_buf[50];
            char footer_buf[25];
            
            if(current_menu != &shareMenu) {
              last_menu_selection = -1;
              current_menu = &shareMenu;
              
              if(current_frog.unlocked && current_frog.validated && current_frog.shareable) { //Don't allow sharing of locked, invalid, or secret reward frogs
                current_menu->options[0] = shareMenuOptionSend;
                current_menu->options[1] = shareMenuOptionReceive;
                current_menu->options[2] = shareMenuOptionBackToFrogs;
                current_menu->num_options = 3;
                sprintf(subtext_buf, "Frog #%d (%s)", current_frog_index + 1, current_frog.name);
              }
              else {
                current_menu->options[0] = shareMenuOptionReceive;
                current_menu->options[1] = shareMenuOptionBackToFrogs;
                current_menu->num_options = 2;
                sprintf(subtext_buf, "");
              }
              
              sprintf(footer_buf, "Shares: %d", num_shares);
              
              current_menu->current_selection = 0;
              didScanNetworks = false;
              didSetupSoftAP = false;
              didDrawStats = false;
              server.end(); //In case back was pressed on an active server
            }

            last_menu_selection = drawMenu(last_menu_selection, NULL, (char *) subtext_buf, (char *) footer_buf);
            break;
          case SEND:
            if(!didScanNetworks) { //If we haven't scanned networks, do it and display a waiting dialog
              if(current_dialog != &scanProgressDialog) {
                last_dialog_progress = -1;
                current_dialog = &scanProgressDialog;
                current_dialog->progress = 0;
                drawProgressDialogStatic(NULL, NULL);
                int num_networks = scanWiFiForFrogs(); //blocking call
                didScanNetworks = true;
                current_dialog->progress++;
                last_dialog_progress = drawProgressDialog(last_dialog_progress);         
              }
            }
            else { //We've finished scanning networks
              switch(current_share_status) {
                case CONNECTING: //Show connecting dialog
                  #ifdef DEBUG_LOG
                  log("State CONNECTING", true);
                  #endif
                  
                  if(!current_frog.unlocked || !current_frog.validated || !current_frog.shareable) { //Don't allow sharing of locked, invalid, or secret reward frogs
                    if(current_menu != &shareMenuNotAllowed) { //Show failure menu with option to go back
                      last_menu_selection = -1;
                      current_menu = &shareMenuNotAllowed;
                      current_menu->current_selection = 0;
                    }
                    last_menu_selection = drawMenu(last_menu_selection, NULL, NULL, NULL);
                  }
                  else {
                    if(current_dialog != &connectionWaitDialog) {
                      #ifdef DEBUG_LOG
                      log("Show connecting dialog", true);
                      #endif
                      
                      last_dialog_progress = -1;
                      current_dialog = &connectionWaitDialog;
                      current_dialog->progress = 0;
                      char msg[] = "Connecting to:";
                      drawProgressDialogStatic((char *) msg, (char *) current_menu->options[current_menu->current_selection].name);

                      //Connect to Frog WiFi
                      #ifdef DEBUG_LOG
                      log("Connecting to WiFi", true);
                      #endif
                      
                      connectToFrogWiFi((char *) current_menu->options[current_menu->current_selection].name);
                      current_dialog->progress++;
                    }
                  }
                  break;
                case SENDING: //Send data
                  #ifdef DEBUG_LOG
                  log("State SENDING", true);
                  #endif
                  
                  if(current_dialog != &connectedTransferDialog) {
                    last_dialog_progress = -1;
                    current_dialog = &connectedTransferDialog;
                    current_dialog->total = 0;
                    current_dialog->progress = 0;
                    char msg[] = "Sending Frog...";
                    drawProgressDialogStatic((char *) msg, (char *) current_frog.name);
                    last_dialog_progress = drawProgressDialog(last_dialog_progress);
                    
                    sendFrog(); 
                  }
                  break;
                case COMPLETE_FAILURE: //Show failure dialog
                  #ifdef DEBUG_LOG
                  log("State FAILURE", true);
                  #endif
                  
                  if(current_menu != &shareMenuFailure) { //Show failure menu with option to go back
                    last_menu_selection = -1;
                    current_menu = &shareMenuFailure;
                    current_menu->current_selection = 0;
                  }
                  last_menu_selection = drawMenu(last_menu_selection, NULL, NULL, NULL);
                  break;
                case COMPLETE_SUCCESS: //Show success dialog
                  #ifdef DEBUG_LOG
                  log("State SUCCESS", true);
                  #endif
                  
                  if(current_menu != &shareMenuSuccess) { //Show success menu with option to go back
                    last_menu_selection = -1;
                    current_menu = &shareMenuSuccess;
                    current_menu->current_selection = 0;
                  }
                  last_menu_selection = drawMenu(last_menu_selection, NULL, NULL, NULL);
                  break;
                default:
                  #ifdef DEBUG_LOG
                  log("State DEFAULT", true);
                  #endif
                  
                  if(current_menu != &shareMenuSend) { //Show available frogs to connect to
                    last_menu_selection = -1;
                    current_menu = &shareMenuSend;
                    current_menu->current_selection = 0;
                  }
                  last_menu_selection = drawMenu(last_menu_selection, NULL, NULL, NULL);
                  break;
              }
            }
            vTaskDelay((RENDER_DELAY_PROGRESS - RENDER_DELAY) / portTICK_PERIOD_MS);
            break;
          case RECEIVE:
            if(!didSetupSoftAP) {
              if(current_dialog != &apProgressDialog) {
                last_dialog_progress = -1;
                current_dialog = &apProgressDialog;
                current_dialog->progress = 0;
                drawProgressDialogStatic(NULL, NULL);
                createSoftAP(); //blocking call
                didSetupSoftAP = true;
                current_dialog->progress++;
                last_dialog_progress = drawProgressDialog(last_dialog_progress);         
              }
            }
            else {
              switch(current_share_status) {
                case RECEIVING:
                  if(current_dialog != &connectedTransferDialog) {
                    last_dialog_progress = -1;
                    current_dialog = &connectedTransferDialog;
                    //current_dialog->total = current_frog.num_frames + 2; //1 additional for connect, 1 additional to send ID string
                    current_dialog->progress = 0;
                    char msg[] = "Receiving Frog...";
                    char subtext[] = "This may take a few minutes";
                    drawProgressDialogStatic((char *) msg, subtext);
                    last_dialog_progress = drawProgressDialog(last_dialog_progress);
                    
                    WiFiClient client = server.available();
                    receiveFrog(client);
                  }
                  break;
                case COMPLETE_FAILURE: //Show failure dialog
                  #ifdef DEBUG_LOG
                  log("State FAILURE", true);
                  #endif
                  
                  if(current_menu != &shareMenuFailure) { //Show failure menu with option to go back
                    last_menu_selection = -1;
                    current_menu = &shareMenuFailure;
                    current_menu->current_selection = 0;
                  }
                  last_menu_selection = drawMenu(last_menu_selection, NULL, NULL, NULL);
                  server.end();
                  break;
                case COMPLETE_SUCCESS: //Show success dialog
                  #ifdef DEBUG_LOG
                  log("State SUCCESS", true);
                  #endif
                  
                  if(current_menu != &shareMenuSuccess) { //Show success menu with option to go back
                    last_menu_selection = -1;
                    current_menu = &shareMenuSuccess;
                    current_menu->current_selection = 0;
                  }
                  last_menu_selection = drawMenu(last_menu_selection, NULL, NULL, NULL);
                  server.end();
                  break; 
                default: //CONNECTING state goes here too
                  if(current_dialog != &connectionWaitDialog) {
                    last_dialog_progress = -1;
                    current_dialog = &connectionWaitDialog;
                    current_dialog->progress = 0;
                    drawProgressDialogStatic(NULL, (char *) NAME);
                    
                    server = WiFiServer(SHARE_PORT);
                    server.begin();
                  }
                  
                  #ifdef DEBUG_LOG
                  log("Waiting for connection...", true);
                  #endif
                  
                  if(server.hasClient()) {
                    xSemaphoreTake(lock, 200 / portTICK_PERIOD_MS);
                    setShareStatus(RECEIVING);
                    xSemaphoreGive(lock);
                  }
              }
            }
            vTaskDelay((RENDER_DELAY_PROGRESS - RENDER_DELAY) / portTICK_PERIOD_MS);
            break;
        }
        vTaskDelay(RENDER_DELAY / portTICK_PERIOD_MS);
      }
      else if(current_mode == STATS) {
        if(!didDrawStats) {
          didDrawStats = drawStatsScreen();
        }
        vTaskDelay(RENDER_DELAY_STATS / portTICK_PERIOD_MS);
      }
      else if(current_mode == TEMPERATURE) {
        if(!current_cold_frog_unlocked) { //If we haven't unlocked the cold frog
          //Get current temperature and humidity
          sensors_event_t humidity, temp;
          temp_sensor.getEvent(&humidity, &temp);
          sprintf(current_temperature, "%.1f", temp.temperature);
          
          //Draw temperature screen if temperature has changed
          if(strncmp(current_temperature, last_temperature, 10) != 0) {
            drawTemperatureScreen(temp.temperature);
            sprintf(last_temperature, "%.1f", temp.temperature);
          }
        }
        vTaskDelay(RENDER_DELAY_TEMPERATURE / portTICK_PERIOD_MS);
      }
  }
}

/* Connectivity */
int scanWiFiForFrogs() {
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  vTaskDelay(100 / portTICK_PERIOD_MS);
  int num_networks = WiFi.scanNetworks(false, false, false, WIFI_CHANNEL_SCAN_MS, SHARE_WIFI_CHANNEL, NULL, NULL);
  int num_frogs = 0;
  
  #ifdef DEBUG_LOG
  char log_line[20];
  snprintf(log_line, 20, "Found %d network(s)", num_networks);
  log(log_line, true);
  #endif
  
  for(int i = 0; i < num_networks; i++) {
    if(num_frogs < MAX_MENU_OPTIONS - 1 && strstr(WiFi.SSID(i).c_str(), "FROG_") != NULL) { //Save last menu option for the "try scan again" choice
      strncpy(shareMenuSend.options[num_frogs].name, WiFi.SSID(i).c_str() + 5, 50);
      shareMenuSend.options[num_frogs].action = connectToFrog; //todo: add connect option function 
      shareMenuSend.options[num_frogs].color_inactive = TFT_BLACK;
      shareMenuSend.options[num_frogs].color_active = TFT_BLUE;
      shareMenuSend.options[num_frogs].text_color = TFT_WHITE;
      num_frogs++;
    }
  }
  
  //Add option to try scan again
  char back_text[] = "[Back]";
  strncpy(shareMenuSend.options[num_frogs].name, (const char *) back_text, strlen(back_text) + 1);
  shareMenuSend.options[num_frogs].action = setShareTypeNone;
  shareMenuSend.options[num_frogs].color_inactive = TFT_BLACK;
  shareMenuSend.options[num_frogs].color_active = TFT_BLUE;
  shareMenuSend.options[num_frogs].text_color = TFT_WHITE;

  shareMenuSend.num_options = num_frogs + 1;
  return num_frogs;
}

void generatePSKForWiFi(char *ssid, char *psk_output) {
  int ssid_idx = 0;
  int psk_idx = 0;
  int code1 = 0;
  int code2 = 0;
  for(ssid_idx = 0; ssid_idx < strlen(ssid); ssid_idx += 2) {
    psk_output[psk_idx++] = ssid[ssid_idx];
    code1 ^= (int) ssid[ssid_idx];
    code2 += (int) ssid[ssid_idx];
  }
  psk_output += sprintf(psk_output + psk_idx, "%d%d", code1, code2);  
  psk_output[psk_idx] = '\0';
}

bool createSoftAP() {
  //Re-generate ECC public/private keypair before enabling soft AP
  uECC_make_key(my_ecc_public, my_ecc_private, ecc_curve);
  
  WiFi.mode(WIFI_AP);
  WiFi.disconnect();
  vTaskDelay(100 / portTICK_PERIOD_MS);
  char buf[50];
  char psk[50];
  sprintf(buf, "%s", NAME); //SSID without leading "FROG_"
  generatePSKForWiFi((char *) buf, (char *) psk);
  sprintf(buf, "%s_%s", "FROG", NAME);
  
  #ifdef DEBUG_LOG
  char log_line[100];
  snprintf(log_line, 100, "SSID=%s, PSK=%s", buf, psk);
  log(log_line, true);
  #endif
  
  bool retval = WiFi.softAP((const char *) buf, (const char *) psk, SHARE_WIFI_CHANNEL, 0, 1, false);
  
  if(retval) { //If we set up the soft AP successfully, set the status to CONNECTING while we wait for a frog client to connect
    xSemaphoreTake(lock, 200 / portTICK_PERIOD_MS);
    setShareStatus(CONNECTING);
    xSemaphoreGive(lock);    
  }
  
  return retval;
}

bool connectToFrogWiFi(char *ssid) {
  //Re-generate ECC public/private keypair before connecting
  uECC_make_key(my_ecc_public, my_ecc_private, ecc_curve);
  
  char buf[50];
  char psk[50];
  sprintf(buf, "FROG_%s", ssid);

  generatePSKForWiFi((char *) ssid, (char *) psk);
  
  #ifdef DEBUG_LOG
  char log_line[100];
  snprintf(log_line, 100, "Connect to frog: SSID=%s, PSK=%s", (char *) buf, (char *) psk);
  log(log_line, true);
  #endif

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  vTaskDelay(100 / portTICK_PERIOD_MS);
  WiFi.begin(buf, psk);

  uint8_t num_attempts = 0;
  while (num_attempts < WIFI_MAX_CONNECT_ATTEMPTS && WiFi.status() != WL_CONNECTED) {
    vTaskDelay(500 / portTICK_PERIOD_MS);
    num_attempts++;
  }

  wl_status_t status = WiFi.status();
  if(status != WL_CONNECTED) {
    WiFi.disconnect();
    xSemaphoreTake(lock, 200 / portTICK_PERIOD_MS);
    setShareStatus(COMPLETE_FAILURE);
    xSemaphoreGive(lock);    
  }
  else {
    xSemaphoreTake(lock, 200 / portTICK_PERIOD_MS);
    setShareStatus(SENDING);
    xSemaphoreGive(lock);
  }
  
  return status == WL_CONNECTED;
}

uint8_t waitOrTimeoutConnection(WiFiClient client) {
  unsigned long task_timeout = millis() + TASK_TIMEOUT_MS; //Keeps track of how long we've been waiting
  while(!client.available()) {
    //vTaskDelay(1 / portTICK_PERIOD_MS);
    if(millis() > task_timeout) {
      #ifdef DEBUG_LOG
      log("Connection timed out!", true);
      #endif
      return 1; //Indicates timeout occurred
    }
  }
  
  return 0; //Indicates client is ready with data
}

void receiveFrog(WiFiClient client) {
  if(client.connected()) {
    #ifdef DEBUG_LOG
    char log_line[1000];
    log("Client connected", true);
    #endif
    
    xSemaphoreTake(lock, 200 / portTICK_PERIOD_MS);
    setShareStatus(RECEIVING);
    xSemaphoreGive(lock);
    
    //Set up buffers
    uint8_t sender_public[40] = {0};
    uint8_t shared_secret[20] = {0};
    //Generated shared secret is 20 bytes in length. AES needs 128, 192, or 256. Set length to 17 bytes and truncate
    char aes_key[17] = {0}; //Hex string equivalent of shared secret
    uint8_t enc_buf[200] = {0}; //Buffer to hold encrypted messages
    uint8_t dec_buf[200] = {0}; //Buffer to hold decrypted messages
    
    while(!client.available());
    
    //Receive public key from sender
    client.readBytes((unsigned char *) sender_public, sizeof(sender_public));
    #ifdef DEBUG_LOG
    log("Read public key from sender", true);
    #endif
    
    //Share public key with sender
    client.write(my_ecc_public, sizeof(my_ecc_public));
    client.flush();
    delay(100);
    #ifdef DEBUG_LOG
    log("Sent public key to sender", true);
    #endif
    
    //Calculate shared secret to be used as encryption key
    uECC_shared_secret(sender_public, my_ecc_private, shared_secret, ecc_curve);
    makeAESKeyFromSharedSecret(shared_secret, sizeof(shared_secret), (char *) aes_key);
    #ifdef DEBUG_LOG
    log("Generated shared secret and AES key: ", false);
    snprintf(log_line, sizeof(aes_key), "%s", aes_key);
    log(log_line, true);
    #endif
    
    //Receive encrypted ID of frog to unlock from sender
    while(!client.available());
    
    client.readBytes((unsigned char *) enc_buf, sizeof(enc_buf));
    decrypt((unsigned char *) enc_buf, (const char *) aes_key, (unsigned char *) dec_buf);
    #ifdef DEBUG_LOG
    log("Read frog ID from sender: ", false);
    snprintf(log_line, 20, "%s", (const char *) dec_buf);
    log(log_line, true);
    #endif
    
    client.stop();
    
    //Disconnect from frog
    WiFi.disconnect(true, true); //Disconnect and turn off WiFi
    WiFi.mode(WIFI_OFF);
    
    uint8_t matched_frog_index = 254; //Check pre-calculated hashes and see if what we received from sender matches
    for(int i = 0; i < NUM_FROGS; i++) {
      if(strncmp(frogs[i].id, (const char *) dec_buf, strlen(frogs[i].id)) == 0) {
        matched_frog_index = i;
        break;
      }
    }
    
    xSemaphoreTake(lock, 1000 / portTICK_PERIOD_MS);
    if(matched_frog_index >= 0 && matched_frog_index < NUM_FROGS) { //If there's a match, unlock the frog
      //Set success status
      setShareStatus(COMPLETE_SUCCESS);
      //Unlock frog that was sent
      frog_index = matched_frog_index;
      setFrogUnlocked((char *) frogs[matched_frog_index].id);
    }
    else { //If no match, we probably received invalid data. Display an error.
      setTransferFailed();
    }
    xSemaphoreGive(lock);  
  }
}

void sendFrog() {
  #ifdef DEBUG_LOG
  char log_line[1000];
  #endif
  
  WiFiClient client;
  
  //Connect to frog listening on SHARE_PORT
  uint8_t num_attempts = 0;
  while(num_attempts < WIFI_MAX_CONNECT_ATTEMPTS && !client.connect(share_receiver_ip, SHARE_PORT)) {
    #ifdef DEBUG_LOG
    log("Connecting...", true);
    #endif
    
    vTaskDelay(500 / portTICK_PERIOD_MS);
    num_attempts++;    
  }

  //If connection failed, return failure and set status
  if(!client.connected()) {
    WiFi.disconnect();
    xSemaphoreTake(lock, 200 / portTICK_PERIOD_MS);
    setShareStatus(COMPLETE_FAILURE);
    xSemaphoreGive(lock);
    return;
  }
  
  //Set up buffers
  Frog current_frog = frogs[frog_index];
  uint8_t enc_buf[200] = {0}; //Buffer to hold encrypted messages
  uint8_t dec_buf[200] = {0}; //Buffer to hold decrypted messages
    
  //Set up ECC
  uint8_t receiver_public[40] = {0};
  uint8_t shared_secret[20] = {0};
  //Generated shared secret is 20 bytes in length. AES needs 128, 192, or 256. Set length to 17 bytes and truncate
  char aes_key[17] = {0}; //Hex string equivalent of shared secret
  
  //Share public key with receiver
  client.write(my_ecc_public, sizeof(my_ecc_public));
  client.flush();
  delay(100);
  
  #ifdef DEBUG_LOG
  log("Sent public key to receiver", true);
  #endif
  
  while(!client.available());
  
  //Receive public key from receiver
  client.readBytes((unsigned char *) receiver_public, sizeof(receiver_public));
  #ifdef DEBUG_LOG
  log("Read public key from receiver", true);
  #endif
  
  //Calculate shared secret to be used as encryption key
  uECC_shared_secret(receiver_public, my_ecc_private, shared_secret, ecc_curve);
  makeAESKeyFromSharedSecret(shared_secret, sizeof(shared_secret), (char *) aes_key);
  #ifdef DEBUG_LOG
  log("Generated shared secret and AES key: ", false);
  snprintf(log_line, sizeof(aes_key), "%s", aes_key);
  log(log_line, true);
  #endif
  
  //Send the id of the frog to unlock, encrypted with shared secret
  encrypt((const char *) current_frog.id, (const char *) aes_key, (unsigned char *) enc_buf);
  for(int i = 0 ; i < 2; i++) {
    client.write((const uint8_t *) enc_buf, sizeof(enc_buf));
    client.flush();
    delay(100);
  }
  #ifdef DEBUG_LOG
  log("Sent frog ID to receiver: ", false);
  snprintf(log_line, 20, "%s", (const char *) current_frog.id);
  log(log_line, true);
  #endif
  
  client.stop();
  
  //Disconnect from frog
  WiFi.disconnect(true, true); //Disconnect and turn off WiFi
  WiFi.mode(WIFI_OFF);
  
  xSemaphoreTake(lock, 400 / portTICK_PERIOD_MS);
  //Increment share count
  incrementShareCount();
  //Set success status
  setShareStatus(COMPLETE_SUCCESS);
  xSemaphoreGive(lock);
}

void checkKeyPattern(uint8_t button_id_pressed) {
  if(keybuf_idx >= KEYBUF_LEN) {
    keybuf_idx = 0;
  }
  keybuf[keybuf_idx++] = button_id_pressed;
 
  if(memcmp(keybuf, KEY_PATTERN_STATS, KEYBUF_LEN) == 0) {
    #ifdef DEBUG_LOG
    log("Key pattern: enable stats mode", true);
    #endif
    mode = STATS; //Set current mode to stats
    memset(keybuf, 0, KEYBUF_LEN); //Reset pattern so we're not stuck
    keybuf_idx = 0;
  }
  
  if(memcmp(keybuf, KEY_PATTERN_TEMPERATURE, KEYBUF_LEN) == 0) {
    if(!cold_frog_unlocked) { //If the cold frog hasn't been unlocked yet, we can consider this pattern
      #ifdef DEBUG_LOG
      log("Key pattern: enable temperature mode", true);
      #endif
      mode = TEMPERATURE; //Set current mode to temperature
      frog_index = 3; //Set current index to cold frog
    }
    memset(keybuf, 0, KEYBUF_LEN); //Reset pattern so we're not stuck
    keybuf_idx = 0;
  }
}

void eventThread( void * pvParameters ){
  ezButton btn_prev_dn(PIN_PREV_DN);
  btn_prev_dn.setDebounceTime(DEBOUNCE_TIME);
  ezButton btn_next_up(PIN_NEXT_UP);
  btn_next_up.setDebounceTime(DEBOUNCE_TIME);
  ezButton btn_share_enter(PIN_SHARE_ENTER);
  btn_share_enter.setDebounceTime(DEBOUNCE_TIME);
  ezButton btn_back_cancel(PIN_BACK_CANCEL);
  btn_back_cancel.setDebounceTime(DEBOUNCE_TIME);
  
  while(true) {
    btn_prev_dn.loop();
    btn_next_up.loop();
    btn_share_enter.loop();
    btn_back_cancel.loop();

    if(btn_prev_dn.isPressed()) {
      xSemaphoreTake(lock, portMAX_DELAY);
    
      switch(mode) {
        case DISPLAY_FROG:
          if(frog_index == 0) { //unsigned int, so will wrap around to 255
            frog_index = NUM_FROGS - 1;
          }
          else {
            frog_index--;
          }
          image_index = 0;
          //writeStateToStorage(SD);
          break;
        case SHARE:
          if(current_menu != NULL) {
            if(current_menu->current_selection == 0) { //unsigned int, so will wrap around to 255
              current_menu->current_selection = current_menu->num_options - 1;
            }
            else {
              current_menu->current_selection--;
            }
          }
          break;
      }

      xSemaphoreGive(lock);
      checkKeyPattern(PIN_PREV_DN);
    }
    if(btn_next_up.isPressed()) {
      xSemaphoreTake(lock, portMAX_DELAY);

      switch(mode) {
        case DISPLAY_FROG:
          frog_index++;
          if(frog_index >= NUM_FROGS) {
            frog_index = 0;
          }
          image_index = 0;
          //writeStateToStorage(SD);
          break;
        case SHARE:
          if(current_menu != NULL) {
            current_menu->current_selection++;
            if(current_menu->current_selection >= current_menu->num_options) {
              current_menu->current_selection = 0;
            }
          }
          break;
      }

      xSemaphoreGive(lock);
      checkKeyPattern(PIN_NEXT_UP);
    }
    if(btn_share_enter.isPressed()) {
      //Share button resets keybuf pattern buffer
      memset(keybuf, 0, KEYBUF_LEN);
      keybuf_idx = 0;
      xSemaphoreTake(lock, portMAX_DELAY);

      switch(mode) {
        case DISPLAY_FROG: //If in display mode, put in share mode
          mode = SHARE;
          break;
        case SHARE:
          if(current_menu != NULL) {
            if(*current_menu->options[current_menu->current_selection].action != NULL) {
              (current_menu->options[current_menu->current_selection].action)((char *) current_menu->options[current_menu->current_selection].name);
            }
          }
          break;
      }
      
      xSemaphoreGive(lock);
    }
    if(btn_back_cancel.isPressed()) {
      xSemaphoreTake(lock, portMAX_DELAY);

      switch(mode) {
        case DISPLAY_FROG:
          break;
        default: //If in share or stats mode, put back in display mode
          current_menu = NULL;
          current_dialog = NULL;
          mode = DISPLAY_FROG;
          share_type = NONE;
          share_status = NOT_SHARING;
          WiFi.disconnect(true, true); //Disconnect and turn off WiFi
          WiFi.mode(WIFI_OFF);
          break;
      }
      
      xSemaphoreGive(lock);
      checkKeyPattern(PIN_BACK_CANCEL);
    }
  }
}

void setup() {
  #ifdef DEBUG_LOG
  Serial.begin(115200);
  #endif
  
  char buf[50] = {0};
  tft.init();
  tft.fillScreen(TFT_BLACK);
  tft.setRotation(0);
  tft.setSwapBytes(true);
  //Draw loading text and set up TFT
  tft.setTextColor(TFT_MAGENTA, TFT_BLACK);
  sprintf(buf, NAME);
  tft.drawCentreString(buf,120,SCR_W_H/2 - 30,2);
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  sprintf(buf, "Loading Frogs...");
  tft.drawCentreString(buf,120,SCR_W_H/2 - 10,2);
  tft.setTextColor(TFT_WHITE, TFT_RED);

  vSemaphoreCreateBinary(lock);
  
  //Set up temperature sensor I2C
  temp_sensor.begin();
  
  #ifdef DEBUG_LOG
  sensors_event_t humidity, temp;
  temp_sensor.getEvent(&humidity, &temp);// populate temp and humidity objects with fresh data
  Serial.printf("Temperature: %f C\n", temp.temperature);
  Serial.printf("RH: %f%%\n", humidity.relative_humidity);
  #endif

  if(!SD.begin(5)){
    #ifdef DEBUG_LOG
    Serial.println("Card Mount Failed");
    #endif
    
    //Draw error message on the screen if we couldn't mount the SD card
    tft.fillRect(0,SCR_W_H/2 - 10,SCR_W_H,16, TFT_RED);
    tft.fillRect(0,SCR_W_H/2 + 5,SCR_W_H,16, TFT_RED);
    sprintf(buf, "Missing or improperly");
    tft.drawCentreString(buf,120,SCR_W_H/2 - 10,2);
    sprintf(buf, "formatted SD card!");
    tft.drawCentreString(buf,120,SCR_W_H/2 + 5,2);
    
    return;
  }
  uint8_t cardType = SD.cardType();

  if(cardType == CARD_NONE){
    #ifdef DEBUG_LOG
    Serial.println("No SD card attached");
    #endif
    
    //Draw error message on the screen if we couldn't mount the SD card
    tft.fillRect(0,SCR_W_H/2 - 10,SCR_W_H,16, TFT_RED);
    tft.fillRect(0,SCR_W_H/2 + 5,SCR_W_H,16, TFT_RED);
    sprintf(buf, "Missing or improperly");
    tft.drawCentreString(buf,120,SCR_W_H/2 - 10,2);
    sprintf(buf, "formatted SD card!");
    tft.drawCentreString(buf,120,SCR_W_H/2 + 5,2);
    return;
  }
  
  #ifdef DEBUG_LOG
  log_file = SD.open("/frog.log", FILE_APPEND);
  log("======================", true);
  log((char *) NAME, true);
  #endif

  //Load config or create if none exists
  loadConfig(SD);
  mode = DISPLAY_FROG;
  share_type = NONE;
  share_status = NOT_SHARING;
  
  //Loading progress config
  uint8_t loading_progress = 0;
  tft.setTextColor(TFT_GREEN, TFT_BLACK);
  
  //Use RF noise captured by the WiFi interface to seed ECC
  WiFi.mode(WIFI_STA);
  uECC_set_rng(&seedRNG);
  WiFi.disconnect(true, true); //Disconnect and turn off WiFi
  WiFi.mode(WIFI_OFF);
  
  /*
    Check if the master unlock image is present on the SD card.
    File must be named "wednesday.jpg" and hash must match UMH
  */
  sprintf(buf, "/wednesday.jpg");
  master_unlock = validateFrog(SD, buf, (char *) UMH);
  
  //Validate integrity of frogs
  //Set initial index to saved index or first frog that's unlocked
  int first_unlocked_frog = -1;
  for(int i = 0; i < NUM_FROGS; i++) {
    Frog frog = frogs[i];
    
    if(strncmp(frog.id, "custom", strlen(frog.id)) == 0) { //Configure custom frog
      //Read directory and set number of frames, up to 50
      int num_custom_frames = getFrogNumFrames((char *) frog.id);
      frogs[i].num_frames = min(num_custom_frames, FROG_MAX_FRAMES);
      frogs[i].validated = true; //Custom frog needs no validation
      if(num_custom_frames > 0) { //If custom frog has frames, set unlocked.
        frogs[i].unlocked = true;
      }
      continue;
    }
    
    //If master image is present and valid, unlock and set valid without additional checks
    if(master_unlock) {
      frogs[i].validated = true;
      frogs[i].unlocked = true;
      
      #ifdef DEBUG_LOG
      log("Master unlock present! Skipping init checks for ", false);
      log((char *) frog.id, true);
      #endif
    }
    else {
      int num_frames = getFrogNumFrames((char *) frog.id);
      if(num_frames == 0) { //If the number of frames on SD card is 0, the folder is empty or does not exist
        frogs[i].validated = false;
        frogs[i].unlocked = false;
      }
      else if(num_frames == frog.num_frames) { //If frames is non-zero, perform an additional check that the number of frames on disk matches config
        sprintf(buf, "/img/%s/0.jpg", frog.id);
        frogs[i].validated = validateFrog(SD, buf, frog.hash);
      }

      if(first_unlocked_frog < 0 && frogs[i].validated && frogs[i].unlocked) {
        first_unlocked_frog = i;      
      }
    }
    
    int progress_pct = (int) ((loading_progress++ / (float) NUM_FROGS) * 100.0f);
    sprintf(buf, "%d%%", progress_pct);
    tft.drawCentreString(buf,120,SCR_W_H/2 + 15,2);
    if(!master_unlock) {
      if(progress_pct == THAT_COOL_NUMBER) {
        sprintf(buf, "(nice)");
        tft.drawCentreString(buf,120,SCR_W_H/2 + 35,2);
      }
      else if(progress_pct > THAT_COOL_NUMBER) { //Make it go away!!!
        tft.fillRect(0,SCR_W_H/2 + 33,SCR_W_H,25, TFT_BLACK);
      }
    }
  }
  
  //Check that at least one frog is valid and unlocked...
  bool all_locked_or_invalid = true;
  for(int i = 0; i < NUM_FROGS; i++) {
    Frog frog = frogs[i];
    if(strncmp(frog.id, "custom", strlen(frog.id)) != 0) {
      if(frog.unlocked || frog.validated) {
        all_locked_or_invalid = false;
        break;
      }
    }
  }
  //...if not, we're most likely dealing with an empty SD card or incorrect directory structure
  if(all_locked_or_invalid) {
    #ifdef DEBUG_LOG
    Serial.println("Couldn't Load Any Frogs!");
    #endif
    
    tft.setTextColor(TFT_WHITE, TFT_RED);
    //Draw error message on the screen if we couldn't mount the SD card
    tft.fillRect(0,SCR_W_H/2 - 10,SCR_W_H,18, TFT_RED);
    tft.fillRect(0,SCR_W_H/2 + 5,SCR_W_H,23, TFT_RED);
    sprintf(buf, "No Frogs found");
    tft.drawCentreString(buf,120,SCR_W_H/2 - 10,2);
    sprintf(buf, "on SD card!");
    tft.drawCentreString(buf,120,SCR_W_H/2 + 5,2);
    
    return;
  }
  
  //Remember the last frog that was displayed. Otherwise, show the first unlock and valid frog
  if(!frogs[frog_index].validated || !frogs[frog_index].unlocked) {
    frog_index = first_unlocked_frog > -1 && first_unlocked_frog < NUM_FROGS ? first_unlocked_frog : 0;
  }

  xTaskCreatePinnedToCore(
      uiThread,   /* Task function. */
      "UIThread",     /* name of task. */
      20000,       /* Stack size of task */
      NULL,        /* parameter of the task */
      1,           /* priority of the task */
      &UITask,      /* Task handle to keep track of created task */
      0);          /* pin task to core 0 */                  
  delay(500);

  xTaskCreatePinnedToCore(
    eventThread,   /* Task function. */
    "EVThread",     /* name of task. */
    15000,       /* Stack size of task */
    NULL,        /* parameter of the task */
    2,           /* priority of the task */
    &EventTask,      /* Task handle to keep track of created task */
    1);          /* pin task to core 1 */
  delay(500);
}

void loop() {}
