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

package com.wasisto.androidkeystoreencryption.model;

/**
 * A holder for both the encrypted data and its initialization vector.
 */
public class EncryptedDataAndIv {

    private byte[] mEncryptedData;

    private byte[] mIv;

    /**
     * Constructs a new {@code EncryptedDataAndIv}.
     */
    public EncryptedDataAndIv() {
    }

    /**
     * Constructs a new {@code EncryptedDataAndIv} with the specified encrypted data and
     * initialization vector.
     *
     * @param encryptedData The encrypted data.
     * @param iv The initialization vector.
     */
    public EncryptedDataAndIv(byte[] encryptedData, byte[] iv) {
        mEncryptedData = encryptedData;
        mIv = iv;
    }

    /**
     * Returns the encrypted data.
     *
     * @return The encrypted data.
     */
    public byte[] getEncryptedData() {
        return mEncryptedData;
    }

    /**
     * Sets the encrypted data.
     *
     * @param encryptedData The encrypted data.
     */
    public void setEncryptedData(byte[] encryptedData) {
        mEncryptedData = encryptedData;
    }

    /**
     * Returns the initialization vector.
     *
     * @return The initialization vector.
     */
    public byte[] getIv() {
        return mIv;
    }

    /**
     * Sets the initialization vector.
     *
     * @param iv The initialization vector.
     */
    public void setIv(byte[] iv) {
        mIv = iv;
    }
}
