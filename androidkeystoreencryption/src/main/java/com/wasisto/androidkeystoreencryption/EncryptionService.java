/*
 * Copyright 2018 Andika Wasisto
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.wasisto.androidkeystoreencryption;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import com.wasisto.androidkeystoreencryption.exception.EncryptionKeyLostException;
import com.wasisto.androidkeystoreencryption.model.EncryptedDataAndIv;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.SecretKeyEntry;
import java.security.PrivateKey;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

import static android.content.Context.MODE_PRIVATE;
import static android.os.Build.VERSION_CODES.KITKAT;
import static android.os.Build.VERSION_CODES.M;
import static android.util.Base64.DEFAULT;
import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;

/**
 * The encryption service.
 */
public class EncryptionService {

    private static final int SIZE_BYTE_BYTES = Byte.SIZE >> 3;
    private static final int SIZE_CHAR_BYTES = Character.SIZE >> 3;
    private static final int SIZE_SHORT_BYTES = Short.SIZE >> 3;
    private static final int SIZE_INT_BYTES = Integer.SIZE >> 3;
    private static final int SIZE_LONG_BYTES = Long.SIZE >> 3;
    private static final int SIZE_FLOAT_BYTES = Float.SIZE >> 3;
    private static final int SIZE_DOUBLE_BYTES = Double.SIZE >> 3;

    private static final String SHARED_PREFERENCES_NAME = "com.wasisto.androidkeystoreencryption";

    private static final String PREFERENCE_ENCRYPTED_AES_SECRET_KEY = "encryptedAesSecretKey";

    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";

    private static final String AES = "AES";
    private static final String RSA = "RSA";

    private static final String AES_SECRET_KEY_ALIAS = "androidKeystoreEncryptionAesSecretKey";
    private static final String RSA_KEYPAIR_ALIAS = "androidKeystoreEncryptionRsaKeyPair";

    private static final String RSA_ECB_PKCS1PADDING = "RSA/ECB/PKCS1Padding";
    private static final String AES_CBC_PKCS7PADDING = "AES/CBC/PKCS7Padding";

    private static final X500Principal CERTIFICATE_SUBJECT = new X500Principal(
            "CN=AndroidKeystoreEncryption");
    private static final BigInteger CERTIFICATE_SERIAL_NUMBER = new BigInteger("1");
    private static final Date CERTIFICATE_NOT_BEFORE = new Date(0L);
    private static final Date CERTIFICATE_NOT_AFTER = new Date(Long.MAX_VALUE);

    private static final int RSA_KEY_SIZE = 4096;
    private static final int AES_KEY_SIZE = 256;

    private static volatile EncryptionService instance;

    private SecretKey aesSecretKey;

    private void initialize(Context context) {
        try {
            KeyStore keystore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keystore.load(null);

            SharedPreferences sharedPreferences = context.getSharedPreferences(
                    SHARED_PREFERENCES_NAME, MODE_PRIVATE);

            if (sharedPreferences.contains(PREFERENCE_ENCRYPTED_AES_SECRET_KEY)) {
                try {
                    String base64EncodedEncryptedAesSecretKey = sharedPreferences.getString(
                            PREFERENCE_ENCRYPTED_AES_SECRET_KEY, null);

                    PrivateKeyEntry rsaKeyPairKeystoreEntry = (PrivateKeyEntry) keystore.getEntry(
                            RSA_KEYPAIR_ALIAS, null);

                    PrivateKey rsaPrivateKey = rsaKeyPairKeystoreEntry.getPrivateKey();

                    Cipher cipher = Cipher.getInstance(RSA_ECB_PKCS1PADDING);
                    cipher.init(DECRYPT_MODE, rsaPrivateKey);

                    byte[] encryptedAesSecretKey = Base64.decode(
                            base64EncodedEncryptedAesSecretKey, DEFAULT);

                    byte[] aesSecretKey = cipher.doFinal(encryptedAesSecretKey);

                    this.aesSecretKey = new SecretKeySpec(aesSecretKey, AES);
                } catch (Throwable t) {
                    throw new EncryptionKeyLostException("The encryption key is lost. Reset " +
                            "using EncryptionService#resetEncryptionKey(Context) method.");
                }
            } else {
                if (Build.VERSION.SDK_INT >= M) {
                    if (keystore.containsAlias(AES_SECRET_KEY_ALIAS)) {
                        SecretKeyEntry aesSecretKeyKeystoreEntry =
                                (SecretKeyEntry) keystore.getEntry(AES_SECRET_KEY_ALIAS,
                                        null);

                        aesSecretKey = aesSecretKeyKeystoreEntry.getSecretKey();
                    } else {
                        KeyGenerator aesSecretKeyGenerator = KeyGenerator.getInstance(AES,
                                ANDROID_KEYSTORE);

                        KeyGenParameterSpec keyGenParameterSpec =
                                new KeyGenParameterSpec.Builder(AES_SECRET_KEY_ALIAS,
                                        KeyProperties.PURPOSE_ENCRYPT
                                                | KeyProperties.PURPOSE_DECRYPT)
                                        .setCertificateSubject(CERTIFICATE_SUBJECT)
                                        .setCertificateSerialNumber(CERTIFICATE_SERIAL_NUMBER)
                                        .setKeyValidityStart(CERTIFICATE_NOT_BEFORE)
                                        .setKeyValidityEnd(CERTIFICATE_NOT_AFTER)
                                        .setKeySize(AES_KEY_SIZE)
                                        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                                        .setEncryptionPaddings(
                                                KeyProperties.ENCRYPTION_PADDING_PKCS7)
                                        .build();

                        aesSecretKeyGenerator.init(keyGenParameterSpec);

                        aesSecretKey = aesSecretKeyGenerator.generateKey();
                    }
                } else {
                    KeyPairGenerator rsaKeyPairGenerator = KeyPairGenerator.getInstance(RSA,
                            ANDROID_KEYSTORE);

                    KeyPairGeneratorSpec.Builder keyPairGeneratorSpecBuilder =
                            new KeyPairGeneratorSpec.Builder(context)
                                    .setAlias(RSA_KEYPAIR_ALIAS)
                                    .setSubject(CERTIFICATE_SUBJECT)
                                    .setSerialNumber(CERTIFICATE_SERIAL_NUMBER)
                                    .setStartDate(CERTIFICATE_NOT_BEFORE)
                                    .setEndDate(CERTIFICATE_NOT_AFTER);

                    if (Build.VERSION.SDK_INT >= KITKAT) {
                        keyPairGeneratorSpecBuilder.setKeySize(RSA_KEY_SIZE);
                    }

                    rsaKeyPairGenerator.initialize(keyPairGeneratorSpecBuilder.build());

                    KeyPair rsaKeyPair = rsaKeyPairGenerator.generateKeyPair();

                    Cipher cipher = Cipher.getInstance(RSA_ECB_PKCS1PADDING);
                    cipher.init(ENCRYPT_MODE, rsaKeyPair.getPublic());

                    KeyGenerator aesSecretKeyGenerator = KeyGenerator.getInstance(AES);
                    aesSecretKeyGenerator.init(AES_KEY_SIZE);

                    aesSecretKey = aesSecretKeyGenerator.generateKey();

                    byte[] encryptedAesSecretKey = cipher.doFinal(aesSecretKey.getEncoded());

                    sharedPreferences.edit().putString(PREFERENCE_ENCRYPTED_AES_SECRET_KEY,
                            Base64.encodeToString(encryptedAesSecretKey, DEFAULT)).apply();
                }
            }
        } catch (GeneralSecurityException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    private EncryptionService(Context context) {
        initialize(context);
    }

    /**
     * Returns the {@code EncryptionService} instance for the current application.
     *
     * @param context The {@code Context}.
     * @return The {@code EncryptionService} instance for the current application.
     */
    public static EncryptionService getInstance(Context context) {
        if (instance == null) {
            synchronized (EncryptionService.class) {
                if (instance == null) {
                    instance = new EncryptionService(context.getApplicationContext());
                }
            }
        }

        return instance;
    }

    /**
     * Asynchronously returns {@code EncryptionService} instance for the current application.
     *
     * @param context The {@code Context}.
     * @param callback The callback.
     */
    public static void getInstanceAsync(Context context, GetInstanceAsyncCallback callback) {
        Handler handler = new Handler(Looper.myLooper() != null ? Looper.myLooper() :
                Looper.getMainLooper());

        new Thread(() -> {
            try {
                EncryptionService instance = getInstance(context);
                handler.post(() -> callback.onSuccess(instance));
            } catch (Throwable t) {
                if (t instanceof EncryptionKeyLostException) {
                    handler.post(() -> callback.onEncryptionKeyLost(
                            (EncryptionKeyLostException) t));
                } else {
                    handler.post(() -> callback.onError(t));
                }
            }
        });
    }

    /**
     * Resets the stored encryption key.
     *
     * @param context The {@code Context}.
     */
    public static synchronized void resetEncryptionKey(Context context) {
        try {
            KeyStore keystore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keystore.load(null);

            keystore.deleteEntry(AES_SECRET_KEY_ALIAS);
            keystore.deleteEntry(RSA_KEYPAIR_ALIAS);

            SharedPreferences sharedPreferences = context.getSharedPreferences(
                    SHARED_PREFERENCES_NAME, MODE_PRIVATE);

            sharedPreferences.edit().clear().apply();

            if (instance != null) {
                instance.initialize(context.getApplicationContext());
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Asynchronously resets the stored encryption key.
     *
     * @param context The {@code Context}.
     * @param callback The callback.
     */
    public static void resetEncryptionKeyAsync(Context context,
                                               ResetEncryptionKeyAsyncCallback callback) {
        Handler handler = new Handler(Looper.myLooper() != null ? Looper.myLooper() :
                Looper.getMainLooper());

        new Thread(() -> {
            try {
                resetEncryptionKey(context);
                handler.post(callback::onSuccess);
            } catch (Throwable t) {
                handler.post(() -> callback.onError(t));
            }
        });
    }

    /**
     * Encrypts a {@code byte} array.
     *
     * @param byteArray The {@code byte} array to be encrypted.
     * @return The encrypted {@code byte} array and its initialization vector.
     */
    public EncryptedDataAndIv encrypt(byte[] byteArray) {
        try {
            Cipher cipher = Cipher.getInstance(AES_CBC_PKCS7PADDING);
            cipher.init(ENCRYPT_MODE, aesSecretKey);

            byte[] encryptedData = cipher.doFinal(byteArray);
            byte[] iv = cipher.getIV();

            EncryptedDataAndIv encryptedDataAndIv = new EncryptedDataAndIv();
            encryptedDataAndIv.setEncryptedData(encryptedData);
            encryptedDataAndIv.setIv(iv);

            return encryptedDataAndIv;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Encrypts a {@code byte}.
     *
     * @param b The {@code byte} to be encrypted.
     * @return The encrypted {@code byte} and its initialization vector.
     */
    public EncryptedDataAndIv encrypt(byte b) {
        return encrypt(ByteBuffer.allocate(SIZE_BYTE_BYTES).put(b).array());
    }

    /**
     * Encrypts a {@code short}.
     *
     * @param s The {@code short} to be encrypted.
     * @return The encrypted {@code short} and its initialization vector.
     */
    public EncryptedDataAndIv encrypt(short s) {
        return encrypt(ByteBuffer.allocate(SIZE_SHORT_BYTES).putShort(s).array());
    }

    /**
     * Encrypts a {@code int}.
     *
     * @param i The {@code int} to be encrypted.
     * @return The encrypted {@code int} and its initialization vector.
     */
    public EncryptedDataAndIv encrypt(int i) {
        return encrypt(ByteBuffer.allocate(SIZE_INT_BYTES).putInt(i).array());
    }

    /**
     * Encrypts a {@code long}.
     *
     * @param l The {@code long} to be encrypted.
     * @return The encrypted {@code long} and its initialization vector.
     */
    public EncryptedDataAndIv encrypt(long l) {
        return encrypt(ByteBuffer.allocate(SIZE_LONG_BYTES).putLong(l).array());
    }

    /**
     * Encrypts a {@code float}.
     *
     * @param f The {@code float} to be encrypted.
     * @return The encrypted {@code float} and its initialization vector.
     */
    public EncryptedDataAndIv encrypt(float f) {
        return encrypt(ByteBuffer.allocate(SIZE_FLOAT_BYTES).putFloat(f).array());
    }

    /**
     * Encrypts a {@code double}.
     *
     * @param d The {@code double} to be encrypted.
     * @return The encrypted {@code double} and its initialization vector.
     */
    public EncryptedDataAndIv encrypt(double d) {
        return encrypt(ByteBuffer.allocate(SIZE_DOUBLE_BYTES).putDouble(d).array());
    }

    /**
     * Encrypts a {@code char}.
     *
     * @param c The {@code char} to be encrypted.
     * @return The encrypted {@code char} and its initialization vector.
     */
    public EncryptedDataAndIv encrypt(char c) {
        return encrypt(ByteBuffer.allocate(SIZE_CHAR_BYTES).putChar(c).array());
    }

    /**
     * Encrypts a {@code String}.
     *
     * @param str The {@code String} to be encrypted.
     * @return The encrypted {@code String} and its initialization vector.
     */
    public EncryptedDataAndIv encrypt(String str) {
        return encrypt(str.getBytes());
    }

    /**
     * Encrypts a {@code BigInteger}.
     *
     * @param bigInteger The {@code BigInteger} to be encrypted.
     * @return The encrypted {@code BigInteger} and its initialization vector.
     */
    public EncryptedDataAndIv encrypt(BigInteger bigInteger) {
        return encrypt(bigInteger.toByteArray());
    }

    /**
     * Decrypts an encrypted {@code byte} array.
     *
     * @param encryptedDataAndIv The encrypted {@code byte} array to be decrypted and its
     * initialization vector.
     *
     * @return The decrypted {@code byte} array.
     */
    public byte[] decryptByteArray(EncryptedDataAndIv encryptedDataAndIv) {
        try {
            Cipher cipher = Cipher.getInstance(AES_CBC_PKCS7PADDING);
            cipher.init(DECRYPT_MODE, aesSecretKey,
                    new IvParameterSpec(encryptedDataAndIv.getIv()));

            return cipher.doFinal(encryptedDataAndIv.getEncryptedData());
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Decrypts an encrypted {@code byte}.
     *
     * @param encryptedDataAndIv The encrypted {@code byte} to be decrypted and its initialization
     * vector.
     *
     * @return The decrypted {@code byte}.
     */
    public byte decryptByte(EncryptedDataAndIv encryptedDataAndIv) {
        return ByteBuffer.wrap(decryptByteArray(encryptedDataAndIv)).get();
    }

    /**
     * Decrypts an encrypted {@code short}.
     *
     * @param encryptedDataAndIv The encrypted {@code short} to be decrypted and its initialization
     * vector.
     *
     * @return The decrypted {@code short}.
     */
    public short decryptShort(EncryptedDataAndIv encryptedDataAndIv) {
        return ByteBuffer.wrap(decryptByteArray(encryptedDataAndIv)).getShort();
    }

    /**
     * Decrypts an encrypted {@code int}.
     *
     * @param encryptedDataAndIv The encrypted {@code int} to be decrypted and its initialization
     * vector.
     *
     * @return The decrypted {@code int}.
     */
    public int decryptInt(EncryptedDataAndIv encryptedDataAndIv) {
        return ByteBuffer.wrap(decryptByteArray(encryptedDataAndIv)).getInt();
    }

    /**
     * Decrypts an encrypted {@code long}.
     *
     * @param encryptedDataAndIv The encrypted {@code long} to be decrypted and its initialization
     * vector.
     *
     * @return The decrypted {@code long}.
     */
    public long decryptLong(EncryptedDataAndIv encryptedDataAndIv) {
        return ByteBuffer.wrap(decryptByteArray(encryptedDataAndIv)).getLong();
    }

    /**
     * Decrypts an encrypted {@code float}.
     *
     * @param encryptedDataAndIv The encrypted {@code float} to be decrypted and its initialization
     * vector.
     *
     * @return The decrypted {@code float}.
     */
    public float decryptFloat(EncryptedDataAndIv encryptedDataAndIv) {
        return ByteBuffer.wrap(decryptByteArray(encryptedDataAndIv)).getFloat();
    }

    /**
     * Decrypts an encrypted {@code double}.
     *
     * @param encryptedDataAndIv The encrypted {@code double} to be decrypted and its initialization
     * vector.
     *
     * @return The decrypted {@code double}.
     */
    public double decryptDouble(EncryptedDataAndIv encryptedDataAndIv) {
        return ByteBuffer.wrap(decryptByteArray(encryptedDataAndIv)).getDouble();
    }

    /**
     * Decrypts an encrypted {@code char}.
     *
     * @param encryptedDataAndIv The encrypted {@code char} to be decrypted and its initialization
     * vector.
     *
     * @return The decrypted {@code char}.
     */
    public char decryptChar(EncryptedDataAndIv encryptedDataAndIv) {
        return ByteBuffer.wrap(decryptByteArray(encryptedDataAndIv)).getChar();
    }

    /**
     * Decrypts an encrypted {@code String}.
     *
     * @param encryptedDataAndIv The encrypted {@code String} to be decrypted and its initialization
     * vector.
     *
     * @return The decrypted {@code String}.
     */
    public String decryptString(EncryptedDataAndIv encryptedDataAndIv) {
        return new String(decryptByteArray(encryptedDataAndIv));
    }

    /**
     * Decrypts an encrypted {@code BigInteger}.
     *
     * @param encryptedDataAndIv The encrypted {@code BigInteger} to be decrypted and its
     * initialization vector.
     *
     * @return The decrypted {@code BigInteger}.
     */
    public BigInteger decryptBigInteger(EncryptedDataAndIv encryptedDataAndIv) {
        return new BigInteger(decryptByteArray(encryptedDataAndIv));
    }

    /**
     * The callback interface for the
     * {@link #getInstanceAsync(Context, GetInstanceAsyncCallback)} method.
     */
    public interface GetInstanceAsyncCallback {

        /**
         * Called if the operation is successful.
         *
         * @param instance The {@code EncryptionService} instance.
         */
        void onSuccess(EncryptionService instance);

        /**
         * Called if the encryption key is lost.
         *
         * @param e The exception.
         */
        void onEncryptionKeyLost(EncryptionKeyLostException e);

        /**
         * Called if an error occurred.
         *
         * @param error The error.
         */
        void onError(Throwable error);
    }

    /**
     * The callback interface for the
     * {@link #resetEncryptionKeyAsync(Context, ResetEncryptionKeyAsyncCallback)} method.
     */
    public interface ResetEncryptionKeyAsyncCallback {

        /**
         * Called if the operation is successful.
         */
        void onSuccess();

        /**
         * Called if an error occurred.
         *
         * @param error The error.
         */
        void onError(Throwable error);
    }
}
