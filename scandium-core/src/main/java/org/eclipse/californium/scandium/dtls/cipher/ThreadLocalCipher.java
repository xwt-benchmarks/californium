/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Achim Kraus (Bosch Software Innovations GmbH) - initial implementation.
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.cipher;

import org.checkerframework.checker.crypto.qual.AllowedAlgorithms;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;

/**
 * Thread local cipher.
 * 
 * Uses {@link ThreadLocal} to cache calls to
 * {@link Cipher#getInstance(String)}.
 */
public class ThreadLocalCipher extends ThreadLocalCrypto<Cipher> {

	/**
	 * {@inheritDoc} Create thread local cipher.
	 * 
	 * Try to instance the cipher for the provided transformation.
	 * 
	 * @param transformation transformation. Passed to
	 *            {@link Cipher#getInstance(String)}.
	 */
	public ThreadLocalCipher(final @AllowedAlgorithms({"((PBEWith(SHA256|HmacSHA1|HmacSHA224|HmacSHA256|HmacSHA384|HmacSHA512)And(DESede|TripleDES|2KeyTripleDES|3KeyTripleDES|AES_128|AES_256))|AES|AES_128|AES_256|AESWrap|ARCFOUR|ECIES|RC5|RSA)\\/(NONE|CBC|GCM|CCM|CFB|CTR|CTS|OFB|PCBC)\\/(NoPadding|ISO10126Padding|OAEPPadding|PKCS1Padding|PKCS5Padding|PKCS7Padding|SSL3Padding|(OAEPWith(SHA-224|SHA-256|SHA-384|SHA-512)AndMGF1Padding))", "RSA", "RSA\\/ECB\\/(NoPadding|ISO10126Padding|OAEPPadding|PKCS1Padding|PKCS5Padding|PKCS7Padding|SSL3Padding|(OAEPWith(SHA-224|SHA-256|SHA-384|SHA-512)AndMGF1Padding))", "PBEWith(SHA256|HmacSHA1|HmacSHA224|HmacSHA256|HmacSHA384|HmacSHA512)And(DESede|TripleDES|2KeyTripleDES|3KeyTripleDES|AES_128|AES_256)"}) String transformation) {
		super(new Factory<Cipher>() {

			@Override
			public Cipher getInstance() throws GeneralSecurityException {
				return Cipher.getInstance(transformation);
			}

		});
	}

}
