/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.parashar.e2e.service;

import com.parashar.e2e.dto.SerializedKeyPair;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.logging.Level;
import lombok.extern.java.Log;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 *
 * @author parashar
 */

@Log
@Service
public class ECCService {
    @Value("${forwardsecrecy.ecc.curve:curve25519}")
    String curve;
    @Value("${forwardsecrecy.ecc.algorithm:EC}")
    String algorithm;
    @Value("${forwardsecrecy.ecc.provider:BC}")
    String provider;

    private KeyPair generateKey()
            throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator kpg;
        kpg = KeyPairGenerator.getInstance(algorithm, provider);

        X9ECParameters ecP = CustomNamedCurves.getByName(curve);
        ECParameterSpec ecSpec = EC5Util.convertToSpec(ecP);
        kpg.initialize(ecSpec);

        final KeyPair kp = kpg.genKeyPair();
        log.info("Key pair generated " + kp.getPublic().getAlgorithm());
        return kp;
    }

    public SerializedKeyPair getKeyPair()
            throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {

        final KeyPair kp = this.generateKey();
        final String privateKey = this.getPEMEncodedStream(kp.getPrivate(),true);
        log.info("Private Key: \n"+privateKey);
        final String publicKey = this.getPEMEncodedStream(kp.getPublic(), false);
        log.info("Public Key: \n"+publicKey);
        final SerializedKeyPair serializedKeyPair = new SerializedKeyPair(publicKey, privateKey);
        return serializedKeyPair;
    }

    private String getPEMEncodedStream(final Key key, boolean privateKey) {

        final PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(key.getEncoded());
        final StringBuilder sb = new StringBuilder();
//        final String keyType = privateKey ? "PRIVATE" : "PUBLIC";
//        sb.append("-----BEGIN " + keyType + " KEY-----");
        sb.append(new String(Base64.getEncoder().encode(pkcs8KeySpec.getEncoded())));
//        sb.append("-----END " + keyType + " KEY-----");
        return sb.toString();
    }

    public Key getPEMDecodedStream(final String pemEncodedKey, boolean privateKey)
            throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
                
        String encodedKey = pemEncodedKey;
        
        
        
//        if (pemEncodedKey.startsWith("-----BEGIN PRIVATE KEY-----")) {
//            privateKey = true;
//            encodedKey = pemEncodedKey.replaceAll("-----BEGIN PRIVATE KEY-----", "")
//                    .replaceAll("-----END PRIVATE KEY-----", "");
//        } else {
//            encodedKey = pemEncodedKey.replaceAll("-----BEGIN PUBLIC KEY-----", "")
//                    .replaceAll("-----END PUBLIC KEY-----", "");
//        }
        
        final byte[] pkcs8EncodedKey = Base64.getDecoder().decode(encodedKey);
        
        KeyFactory factory = KeyFactory.getInstance(algorithm, provider);
        log.log(Level.FINE, "Successfully initialised the key factory");

        if(privateKey){
            log.log(Level.FINE, "Its a private key");
            KeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedKey);
            //This does not mean the key is in correct format. If you receive invalid key spec error then the encoding is not correct.
            log.log(Level.FINE, "PKCS8 decoded");
            return factory.generatePrivate(keySpec);
        }
        log.log(Level.FINE, "Its a public key");
        KeySpec keySpec = new X509EncodedKeySpec(pkcs8EncodedKey);        
        //This does not mean the key is in correct format. If you receive invalid key spec error then the encoding is not correct.
        log.log(Level.FINE, "X509 decoded");
        return factory.generatePublic(keySpec);

    }

}
