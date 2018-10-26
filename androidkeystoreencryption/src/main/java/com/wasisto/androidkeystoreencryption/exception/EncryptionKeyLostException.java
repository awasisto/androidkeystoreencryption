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

package com.wasisto.androidkeystoreencryption.exception;

/**
 * An exception that will be thrown when the encryption key is lost.
 */
public class EncryptionKeyLostException extends Exception {

    /**
     * Constructs a new {@code EncryptionKeyLostException} with the specified detail message.
     *
     * @param message The detail message.
     */
    public EncryptionKeyLostException(String message) {
        super(message);
    }
}