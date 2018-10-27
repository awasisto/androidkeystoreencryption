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

import android.support.test.runner.AndroidJUnit4;

import com.wasisto.androidkeystoreencryption.EncryptionService.GetInstanceAsyncCallback;
import com.wasisto.androidkeystoreencryption.EncryptionService.ResetEncryptionKeyAsyncCallback;
import com.wasisto.androidkeystoreencryption.model.EncryptedDataAndIv;

import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.math.BigInteger;

import static android.support.test.InstrumentationRegistry.getTargetContext;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.notNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;

@RunWith(AndroidJUnit4.class)
public class EncryptionServiceTest {

    @Test
    public void byteArrayEncryptDecrypt() throws Exception {
        byte[] originalData = new byte[]{4, 8, 15, 16, 23, 42};

        EncryptionService encryptionService = EncryptionService.getInstance(getTargetContext());
        
        EncryptedDataAndIv encryptedDataAndIv = encryptionService.encrypt(originalData);

        byte[] decryptedData = encryptionService.decryptByteArray(encryptedDataAndIv);

        assertArrayEquals(originalData, decryptedData);
    }

    @Test
    public void byteEncryptDecrypt() throws Exception {
        byte originalData = 25;

        EncryptionService encryptionService = EncryptionService.getInstance(getTargetContext());

        EncryptedDataAndIv encryptedDataAndIv = encryptionService.encrypt(originalData);

        byte decryptedData = encryptionService.decryptByte(encryptedDataAndIv);

        assertEquals(originalData, decryptedData);
    }

    @Test
    public void shortEncryptDecrypt() throws Exception {
        short originalData = -31421;

        EncryptionService encryptionService = EncryptionService.getInstance(getTargetContext());

        EncryptedDataAndIv encryptedDataAndIv = encryptionService.encrypt(originalData);

        short decryptedData = encryptionService.decryptShort(encryptedDataAndIv);

        assertEquals(originalData, decryptedData);
    }

    @Test
    public void intEncryptDecrypt() throws Exception {
        int originalData = -110883086;

        EncryptionService encryptionService = EncryptionService.getInstance(getTargetContext());

        EncryptedDataAndIv encryptedDataAndIv = encryptionService.encrypt(originalData);

        int decryptedData = encryptionService.decryptInt(encryptedDataAndIv);

        assertEquals(originalData, decryptedData);
    }

    @Test
    public void longEncryptDecrypt() throws Exception {
        long originalData = 836613320883456075L;

        EncryptionService encryptionService = EncryptionService.getInstance(getTargetContext());

        EncryptedDataAndIv encryptedDataAndIv = encryptionService.encrypt(originalData);

        long decryptedData = encryptionService.decryptLong(encryptedDataAndIv);

        assertEquals(originalData, decryptedData);
    }

    @Test
    public void floatEncryptDecrypt() throws Exception {
        float originalData = 3.14159265358979323846f;

        EncryptionService encryptionService = EncryptionService.getInstance(getTargetContext());

        EncryptedDataAndIv encryptedDataAndIv = encryptionService.encrypt(originalData);

        float decryptedData = encryptionService.decryptFloat(encryptedDataAndIv);

        assertEquals(originalData, decryptedData, 0);
    }

    @Test
    public void doubleEncryptDecrypt() throws Exception {
        double originalData = 3.14159265358979323846;

        EncryptionService encryptionService = EncryptionService.getInstance(getTargetContext());

        EncryptedDataAndIv encryptedDataAndIv = encryptionService.encrypt(originalData);

        double decryptedData = encryptionService.decryptDouble(encryptedDataAndIv);

        assertEquals(originalData, decryptedData, 0);
    }

    @Test
    public void charEncryptDecrypt() throws Exception {
        char originalData = 44765;

        EncryptionService encryptionService = EncryptionService.getInstance(getTargetContext());

        EncryptedDataAndIv encryptedDataAndIv = encryptionService.encrypt(originalData);

        char decryptedData = encryptionService.decryptChar(encryptedDataAndIv);

        assertEquals(originalData, decryptedData);
    }

    @Test
    public void stringEncryptDecrypt() throws Exception {
        String originalData = "foo";

        EncryptionService encryptionService = EncryptionService.getInstance(getTargetContext());

        EncryptedDataAndIv encryptedDataAndIv = encryptionService.encrypt(originalData);

        String decryptedData = encryptionService.decryptString(encryptedDataAndIv);

        assertEquals(originalData, decryptedData);
    }

    @Test
    public void bigIntegerEncryptDecrypt() throws Exception {
        BigInteger originalData = new BigInteger("79206892171740488283");

        EncryptionService encryptionService = EncryptionService.getInstance(getTargetContext());

        EncryptedDataAndIv encryptedDataAndIv = encryptionService.encrypt(originalData);

        BigInteger decryptedData = encryptionService.decryptBigInteger(encryptedDataAndIv);

        assertEquals(originalData, decryptedData);
    }

    @Test
    public void resetEncryptionKey() {
        EncryptionService.resetEncryptionKey(getTargetContext());
    }

    @Test
    public void getInstanceAsync() {
        GetInstanceAsyncCallback callbackMock = mock(GetInstanceAsyncCallback.class);

        EncryptionService.getInstanceAsync(getTargetContext(), callbackMock);

        verify(callbackMock, timeout(60 * 1000)).onSuccess(notNull());
    }

    @Test
    public void resetEncryptionKeyAsync() {
        ResetEncryptionKeyAsyncCallback callbackMock = mock(ResetEncryptionKeyAsyncCallback.class);

        EncryptionService.resetEncryptionKeyAsync(getTargetContext(), callbackMock);

        verify(callbackMock, timeout(60 * 1000)).onSuccess();
    }

    @After
    public void tearDown() {
        EncryptionService.resetEncryptionKey(getTargetContext());
    }
}
