/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.parashar.e2e.service;

import com.parashar.e2e.dto.HKDFInput;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import keywhiz.hkdf.Hash;
import keywhiz.hkdf.Hkdf;
import lombok.extern.java.Log;
import org.springframework.stereotype.Service;

/**
 *
 * @author parashar
 */

@Log
@Service
public class HKDFService {
    
    private Hash hash = Hash.SHA256;

    private Hkdf hkdf = Hkdf.usingHash(hash);
           
    
    public String getHKDFSessionKeyForEncryption(HKDFInput hkdfInput){
        
        String partialKey = getHKDFKey(hkdfInput.getOurRandom(), hkdfInput.getSharedSecret());
        
        String sessionKey = getHKDFKey(hkdfInput.getRemoteRandom(), partialKey);
        
        return sessionKey;
    }

        
    public String getHKDFSessionKeyForDecryption(HKDFInput hkdfInput){
        
        String partialKey = getHKDFKey(hkdfInput.getRemoteRandom(), hkdfInput.getSharedSecret());
        
        String sessionKey = getHKDFKey(hkdfInput.getOurRandom(), partialKey);
        
        return sessionKey;
    }
    
    public String getHKDFKey(int keyOne, String keyTwo){
        
        SecretKey salt = new SecretKeySpec(intToBytes(keyOne), hash.getAlgorithm()); 
        
        SecretKey extractedKey = hkdf.extract(salt, keyTwo.getBytes(StandardCharsets.UTF_8));
        
        byte[] expandedBytes = hkdf.expand(extractedKey, "".getBytes(), hash.getByteLength());
        final PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(expandedBytes);
        final StringBuilder sb = new StringBuilder();
//        final String keyType = privateKey ? "PRIVATE" : "PUBLIC";
//        sb.append("-----BEGIN " + keyType + " KEY-----");
        sb.append(Base64.getEncoder().encodeToString(pkcs8KeySpec.getEncoded()));
//        sb.append("-----END " + keyType + " KEY-----");
        return sb.toString();
    }
    
    private byte[] intToBytes( int i ) {
        ByteBuffer bb = ByteBuffer.allocate(8); 
        bb.putInt(i); 
        return bb.array();
    }
    
}
