/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.parashar.e2e.service;

import com.parashar.e2e.dto.DecryptionSpec;
import com.parashar.e2e.dto.EncryptionSpec;
import com.parashar.e2e.dto.HKDFInput;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import keywhiz.hkdf.Hash;
import keywhiz.hkdf.Hkdf;
import lombok.extern.java.Log;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Value;
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
    
    public String encryptData(EncryptionSpec encryptionSpec) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
        SecretKey secretKey = new SecretKeySpec(Base64.getDecoder().decode(encryptionSpec.getSessionKey()), "AES");
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[12]; //NEVER REUSE THIS IV WITH SAME KEY
        secureRandom.nextBytes(iv);
        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv); //128 bit auth tag length
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        byte[] cipherText = cipher.doFinal(encryptionSpec.getXml().getBytes(StandardCharsets.UTF_8));
        ByteBuffer byteBuffer = ByteBuffer.allocate(4 + iv.length + cipherText.length);
        byteBuffer.putInt(iv.length);
        byteBuffer.put(iv);
        byteBuffer.put(cipherText);
        byte[] cipherMessage = byteBuffer.array();
        return Base64.getEncoder().encodeToString(cipherMessage);
    }

    public String decryptData(DecryptionSpec decryptionSpec) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
        
        
        ByteBuffer byteBuffer = ByteBuffer.wrap(Base64.getDecoder().decode(decryptionSpec.getEncryptedData()));
        
        SecretKey secretKey = new SecretKeySpec(Base64.getDecoder().decode(decryptionSpec.getSessionKey()), "AES");
        
        int ivLength = byteBuffer.getInt();
        if(ivLength < 12 || ivLength >= 16) { // check input parameter
            throw new IllegalArgumentException("invalid iv length");
        }
        byte[] iv = new byte[ivLength];
        byteBuffer.get(iv);
        byte[] cipherText = new byte[byteBuffer.remaining()];
        byteBuffer.get(cipherText);
        
        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));
        
        byte[] plainText= cipher.doFinal(cipherText);

        return new String(plainText);
    }
    
}
