AndroidKeystoreEncryption
=========================

An easy-to-use encryption library that uses Android Keystore system to securely store the encryption
key.

Features
--------

- Data encryption using AES-256 algorithm
- Securely store the encryption key using Android Keystore system
- Data types that are supported out-of-the-box:
  - byte array
  - byte
  - short
  - int
  - long
  - float
  - double
  - char
  - String
  - BigInteger

Usage
-----

**Encryption**

    String dataToEncrypt = "secret data";

    EncryptionService encryptionService = EncryptionService.getInstance(context);

    EncryptedDataAndIv encryptedDataAndIv = encryptionService.encrypt(dataToEncrypt);

    // Save these values somewhere. You can encode them to Base64 if you need to save them
    // as strings.
    byte[] encryptedData = encryptedDataAndIv.getEncryptedData();
    byte[] iv = encryptedDataAndIv.getIv();

**Decryption**

    EncryptedDataAndIv encryptedDataAndIv = new EncryptedDataAndIv();

    // Use the previously saved encrypted data and IV
    encryptedDataAndIv.setEncryptedData(encryptedData);
    encryptedDataAndIv.setIv(iv);

    EncryptionService encryptionService = EncryptionService.getInstance(context);

    encryptionService.decryptString(encryptedDataAndIv);

API <21 Issue
-------------

Prior API 21, an Android bug may cause the Android Keystore system to lose the encryption key when
the device lock screen is changed. Read about it here:
[Android Security: The Forgetful Keystore](https://doridori.github.io/android-security-the-forgetful-keystore/#sthash.2oefHeqm.dpbs).

If you are going to use this library on API <21, make sure you use it only to encrypt the
recoverable data such as password, API token, etc.

Download
--------

    compile 'com.wasisto.androidkeystoreencryption:androidkeystoreencryption:1.0.0'

License
-------

    Copyright 2018 Andika Wasisto

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
