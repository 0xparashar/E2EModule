/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.parashar.e2e.service;

import com.parashar.e2e.dto.DecryptionParameter;
import com.parashar.e2e.dto.DecryptionSpec;
import com.parashar.e2e.dto.SerializedDecryptedData;
import com.parashar.e2e.dto.SerializedKeyPair;
import com.parashar.e2e.dto.SessionSpec;
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
public class FIUService {
    
    @Autowired
    private ECCService eccService;
    
    @Autowired
    private HKDFService hkdfService;
    
    @Autowired
    private DHService dhService;
    
    @Autowired
    private AESService aesService;
    
    public SessionSpec generateSessionSpec() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException{
        
        SerializedKeyPair keyPair = eccService.getKeyPair();
        
        String privateKey = keyPair.getPrivateKey();
        String publicKey = keyPair.getPublicKey();
        
        SecureRandom secRan = new SecureRandom(); 
        byte[] ranBytes = new byte[Hash.SHA256.getByteLength()];
        secRan.nextBytes(ranBytes);
        
        String nonce = new String(Base64.getEncoder().encode(ranBytes));
        return new SessionSpec(nonce, privateKey, publicKey, null);
    }
    
    public SerializedDecryptedData decrypt(DecryptionParameter decryptionParameter) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
        
        Key ourPrivateKey = eccService.getPEMDecodedStream(decryptionParameter.getOurPrivateKey(), true);

        Key remotePublicKey = eccService.getPEMDecodedStream(decryptionParameter.getRemotePublicKey(), false);

        final String secretKey = dhService.getSharedSecret(
                (PrivateKey) ourPrivateKey,
                (PublicKey) remotePublicKey);        
        
        
        
        byte[] ourNonce = Base64.getDecoder().decode(decryptionParameter.getOurNonce());
        byte[] remoteNonce = Base64.getDecoder().decode(decryptionParameter.getRemoteNonce());
        byte[] salt = hkdfService.xor(ourNonce, remoteNonce);
    
        String sessionKey = hkdfService.getHKDFKey(salt, secretKey);

        String decryptedData = aesService.decryptData(decryptionParameter.getEncryptedData(), sessionKey);
        
        return new SerializedDecryptedData(decryptedData);
    }
    
}
