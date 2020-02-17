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
import lombok.extern.java.Log;
import org.springframework.stereotype.Service;

/**
 *
 * @author parashar
 */
@Log
@Service
public class AESService {

    private final String algorithm = "AES";
    
    final int saltIVOffset = 20;
    
    public String encryptData(EncryptionSpec encryptionSpec) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
        SecretKey secretKey = new SecretKeySpec(Base64.getDecoder().decode(encryptionSpec.getSessionKey()), algorithm);
        byte[] iv = new byte[12]; //NEVER REUSE THIS IV WITH SAME KEY
        byte[] xoredNonce = Base64.getDecoder().decode(encryptionSpec.getXoredNonce());
        //Copy only the last 12 bytes
        System.arraycopy(xoredNonce, saltIVOffset, iv, 0, iv.length);
        
        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv); //128 bit auth tag length
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        byte[] cipherText = cipher.doFinal(encryptionSpec.getXml().getBytes(StandardCharsets.UTF_8));
//        ByteBuffer byteBuffer = ByteBuffer.allocate(4 + iv.length + cipherText.length);
//        byteBuffer.putInt(iv.length);
//        byteBuffer.put(iv);
//        byteBuffer.put(cipherText);
//        byte[] cipherMessage = byteBuffer.array();
        return Base64.getEncoder().encodeToString(cipherText);
    }
    
    
        
    public String encryptData(String sessionKey, String data, String xoredNonce) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
        return encryptData(new EncryptionSpec(data, sessionKey, xoredNonce));
    }

    public String decryptData(DecryptionSpec decryptionSpec) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
        
        
//        ByteBuffer byteBuffer = ByteBuffer.wrap(Base64.getDecoder().decode(decryptionSpec.getEncryptedData()));
        
        SecretKey secretKey = new SecretKeySpec(Base64.getDecoder().decode(decryptionSpec.getSessionKey()), algorithm);
        byte[] xoredNonce = Base64.getDecoder().decode(decryptionSpec.getXoredNonce());

        byte[] iv = new byte[12];
        System.arraycopy(xoredNonce, saltIVOffset, iv, 0, iv.length);
        
//        int ivLength = byteBuffer.getInt();
//        if(ivLength < 12 || ivLength >= 16) { // check input parameter
//            throw new IllegalArgumentException("invalid iv length");
//        }
//        byte[] iv = new byte[ivLength];
//        byteBuffer.get(iv);
//        byte[] cipherText = new byte[byteBuffer.remaining()];
//        byteBuffer.get(cipherText);
        
        byte[] cipherText = Base64.getDecoder().decode(decryptionSpec.getEncryptedData());

        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));
        
        byte[] plainText= cipher.doFinal(cipherText);

        return new String(plainText);
    }
    
    
    public String decryptData(String encryptedData, String sessionKey, String xoredNonce) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
        
        return decryptData(new DecryptionSpec(encryptedData, sessionKey, xoredNonce));
    }    
    
}
