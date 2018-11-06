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

import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import com.wasisto.androidkeystoreencryption.exception.EncryptionKeyLostException;
import com.wasisto.androidkeystoreencryption.model.EncryptedDataAndIv;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.math.BigInteger;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

@RunWith(AndroidJUnit4.class)
public class EncryptionServiceTest {

    private EncryptionService encryptionService;
    
    @Before
    public void setUp() throws EncryptionKeyLostException {
        encryptionService = EncryptionService.getInstance(InstrumentationRegistry
                .getTargetContext());
    }

    @Test
    public void byteArrayEncryptDecrypt() {
        byte[] originalData = new byte[]{4, 8, 15, 16, 23, 42};

        EncryptedDataAndIv encryptedDataAndIv = encryptionService.encrypt(originalData);

        byte[] decryptedData = encryptionService.decryptByteArray(encryptedDataAndIv);

        assertArrayEquals(originalData, decryptedData);
    }

    @Test
    public void byteEncryptDecrypt() {
        byte originalData = 25;

        EncryptedDataAndIv encryptedDataAndIv = encryptionService.encrypt(originalData);

        byte decryptedData = encryptionService.decryptByte(encryptedDataAndIv);

        assertEquals(originalData, decryptedData);
    }

    @Test
    public void shortEncryptDecrypt() {
        short originalData = -31421;

        EncryptedDataAndIv encryptedDataAndIv = encryptionService.encrypt(originalData);

        short decryptedData = encryptionService.decryptShort(encryptedDataAndIv);

        assertEquals(originalData, decryptedData);
    }

    @Test
    public void intEncryptDecrypt() {
        int originalData = -110883086;

        EncryptedDataAndIv encryptedDataAndIv = encryptionService.encrypt(originalData);

        int decryptedData = encryptionService.decryptInt(encryptedDataAndIv);

        assertEquals(originalData, decryptedData);
    }

    @Test
    public void longEncryptDecrypt() {
        long originalData = 836613320883456075L;

        EncryptedDataAndIv encryptedDataAndIv = encryptionService.encrypt(originalData);

        long decryptedData = encryptionService.decryptLong(encryptedDataAndIv);

        assertEquals(originalData, decryptedData);
    }

    @Test
    public void floatEncryptDecrypt() {
        float originalData = 3.14159265358979323846f;

        EncryptedDataAndIv encryptedDataAndIv = encryptionService.encrypt(originalData);

        float decryptedData = encryptionService.decryptFloat(encryptedDataAndIv);

        assertEquals(originalData, decryptedData, 0);
    }

    @Test
    public void doubleEncryptDecrypt() {
        double originalData = 3.14159265358979323846;

        EncryptedDataAndIv encryptedDataAndIv = encryptionService.encrypt(originalData);

        double decryptedData = encryptionService.decryptDouble(encryptedDataAndIv);

        assertEquals(originalData, decryptedData, 0);
    }

    @Test
    public void charEncryptDecrypt() {
        char originalData = 44765;

        EncryptedDataAndIv encryptedDataAndIv = encryptionService.encrypt(originalData);

        char decryptedData = encryptionService.decryptChar(encryptedDataAndIv);

        assertEquals(originalData, decryptedData);
    }

    @Test
    public void stringEncryptDecrypt() {
        String originalData = "foo";

        EncryptedDataAndIv encryptedDataAndIv = encryptionService.encrypt(originalData);

        String decryptedData = encryptionService.decryptString(encryptedDataAndIv);

        assertEquals(originalData, decryptedData);
    }

    @Test
    public void bigIntegerEncryptDecrypt() {
        BigInteger originalData = new BigInteger("79206892171740488283");

        EncryptedDataAndIv encryptedDataAndIv = encryptionService.encrypt(originalData);

        BigInteger decryptedData = encryptionService.decryptBigInteger(encryptedDataAndIv);

        assertEquals(originalData, decryptedData);
    }
}
