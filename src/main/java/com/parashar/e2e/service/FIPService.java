/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.parashar.e2e.service;

import com.parashar.e2e.dto.EncryptedSpec;
import com.parashar.e2e.dto.EncryptionParameter;
import com.parashar.e2e.dto.SerializedKeyPair;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.logging.Level;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import keywhiz.hkdf.Hash;
import lombok.extern.java.Log;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 *
 * @author parashar
 */
@Log
@Service
public class FIPService {
        
    @Autowired
    private ECCService eccService;
    
    @Autowired
    private HKDFService hkdfService;
    
    @Autowired
    private DHService dhService;
    
    @Autowired
    private AESService aesService;
    
    public EncryptedSpec encrypt(EncryptionParameter encryptionParameter) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
        
        
        SerializedKeyPair keyPair = eccService.getKeyPair();
        
        Key ourPrivateKey = eccService.getPEMDecodedStream(keyPair.getPrivateKey(), true);

        Key remotePublicKey = eccService.getPEMDecodedStream(encryptionParameter.getRemotePublicKey(), false);

        final String secretKey = dhService.getSharedSecret(
                (PrivateKey) ourPrivateKey,
                (PublicKey) remotePublicKey);        
        
        
        SecureRandom secRan = new SecureRandom(); 
        byte[] ourNonce = new byte[Hash.SHA256.getByteLength()];
        secRan.nextBytes(ourNonce);
        String randomNonce = new String(Base64.getEncoder().encode(ourNonce));
        log.log(Level.INFO, "random nonce generated");
        byte[] remoteNonce = Base64.getDecoder().decode(encryptionParameter.getRemoteNonce());  
        byte[] salt = hkdfService.xor(ourNonce, remoteNonce);
        
        log.log(Level.INFO, "Got salt");

        String sessionKey = hkdfService.getHKDFKey(salt, secretKey);
        log.log(Level.INFO, "Derived session key");
        
        String encryptedData = aesService.encryptData(sessionKey, encryptionParameter.getData());
        
        return new EncryptedSpec(keyPair.getPublicKey(), keyPair.getPrivateKey(), randomNonce, encryptedData, null);
    }
    
}
