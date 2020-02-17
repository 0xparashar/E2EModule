/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.parashar.e2e.service;

import com.parashar.e2e.dto.DecryptionSpec;
import com.parashar.e2e.dto.EncryptionSpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import keywhiz.hkdf.Hash;
import lombok.extern.java.Log;
import org.springframework.stereotype.Service;

/**
 *
 * @author parashar
 */
@Log
@Service
public class AESService {

    private Hash hash = Hash.SHA256;
    private final String algorithm = "AES";
    
    
    public String encryptData(EncryptionSpec encryptionSpec) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
        SecretKey secretKey = new SecretKeySpec(Base64.getDecoder().decode(encryptionSpec.getSessionKey()), algorithm);
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
    
    
        
    public String encryptData(String sessionKey, String data) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
        return encryptData(new EncryptionSpec(data, sessionKey));
    }

    public String decryptData(DecryptionSpec decryptionSpec) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
        
        
        ByteBuffer byteBuffer = ByteBuffer.wrap(Base64.getDecoder().decode(decryptionSpec.getEncryptedData()));
        
        SecretKey secretKey = new SecretKeySpec(Base64.getDecoder().decode(decryptionSpec.getSessionKey()), algorithm);
        
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
    
    
    public String decryptData(String encryptedData, String sessionKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
        
        return decryptData(new DecryptionSpec(encryptedData, sessionKey));
    }    
    
}
