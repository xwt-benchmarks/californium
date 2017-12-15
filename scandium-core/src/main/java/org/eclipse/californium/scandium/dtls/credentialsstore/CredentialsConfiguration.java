/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Bosch Software Innovations GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.credentialsstore;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.rpkstore.TrustedRpkStore;

/**
 * Credentials configuration single destination.
 */
public interface CredentialsConfiguration {
	/**
	 * Gets the cipher suites the connector should advertise in a DTLS
	 * handshake.
	 * 
	 * @return the supported cipher suites (ordered by preference)
	 */
	CipherSuite[] getSupportedCipherSuites();

	/**
	 * Gets the Identity to use for a PSK based handshake with a given peer.
	 * <p>
	 * A DTLS client uses this method to determine the identity to include in
	 * its <em>CLIENT_KEY_EXCHANGE</em> message during a PSK based DTLS
	 * handshake with the peer.
	 * 
	 * @param inetAddress The IP address of the peer to perform the handshake
	 *            with.
	 * @return The identity to use or <code>null</code> if no peer with the
	 *         given address is registered.
	 * @throws NullPointerException if address is {@code null}.
	 */
	String getIdentity();

	/**
	 * Gets the shared key for a given identity.
	 * <p>
	 * The key is used for mutual authentication during a DTLS handshake.
	 * 
	 * @param identity The identity to look up the key for.
	 * @return The key or <code>null</code> if the given identity is unknown.
	 * @throws NullPointerException if identity is {@code null}.
	 */
	byte[] getKey();

	/**
	 * Gets the private key to use for proving identity to a peer
	 * during a DTLS handshake.
	 * 
	 * @return the key
	 */
	PrivateKey getPrivateKey();

	/**
	 * Gets the public key to send to peers during the DTLS handshake
	 * for authentication purposes.
	 * 
	 * @return the key
	 */
	PublicKey getPublicKey();

	/**
	 * @return The trust store for raw public keys verified out-of-band for
	 *         DTLS-RPK handshakes
	 */
	TrustedRpkStore getRpkTrustStore();

	/**
	 * Gets the certificates forming the chain-of-trust from 
	 * a root CA down to the certificate asserting the server's identity.
	 * 
	 * @return the certificates or <code>null</code> if the connector is
	 * not supposed to support certificate based authentication
	 */
	X509Certificate[] getCertificateChain();

	/**
	 * Gets the trusted root certificates to use when verifying
	 * a peer's certificate during authentication.
	 * 
	 * @return the root certificates
	 */
	X509Certificate[] getTrusts();

	/**
	 * Checks whether the connector will send a <em>raw public key</em>
	 * instead of an X.509 certificate in order to authenticate to the peer
	 * during a DTLS handshake.
	 * 
	 * Note that this property is only relevant for cipher suites using certificate
	 * based authentication.
	 * 
	 * @return <code>true</code> if <em>RawPublicKey</em> is used by the connector
	 */
	Boolean isSendRawKey();
}
