/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.parashar.e2e.controller;

import com.parashar.e2e.dto.DecryptionSpec;
import com.parashar.e2e.dto.EncryptionSpec;
import com.parashar.e2e.dto.ErrorInfo;
import com.parashar.e2e.dto.HKDFInput;
import com.parashar.e2e.dto.SecretKeySpec;
import com.parashar.e2e.dto.SerializedDecryptedData;
import com.parashar.e2e.dto.SerializedEncryptedData;
import com.parashar.e2e.dto.SerializedKeyPair;
import com.parashar.e2e.dto.SerializedNonce;
import com.parashar.e2e.dto.SerializedSecretKey;
import com.parashar.e2e.service.AESService;
import com.parashar.e2e.service.DHService;
import com.parashar.e2e.service.ECCService;
import com.parashar.e2e.service.HKDFService;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import java.nio.ByteBuffer;
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
import keywhiz.hkdf.Hash;
import lombok.extern.java.Log;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 *
 * @author parashar
 */
@Log
@RestController
@RequestMapping("/ecc/v1")
public class ECCController {

    @Autowired
    private ECCService eccService;
    @Autowired
    private DHService dheService;
    @Autowired
    private HKDFService hKDFService;
    @Autowired
    private AESService aESService;

    @ApiOperation(value = "Generate a new ecc key pair")
    @GetMapping(value="/generateKey", produces = "application/json")
    @ApiResponses({ @ApiResponse(code = 201, message = " successfully created"),
			@ApiResponse(code = 400, message = " Request body passed  is null or invalid"),
			@ApiResponse(code = 500, message = " Error occured") })
    public SerializedKeyPair generateKey() {
        try {
            log.info("Generate Key");
            return eccService.getKeyPair();
        }
        catch( NoSuchProviderException | NoSuchAlgorithmException | InvalidAlgorithmParameterException ex){
            log.log(Level.SEVERE, "Unable to generateKey");
            SerializedKeyPair errorKeyPair = new SerializedKeyPair("", "");
            ErrorInfo error = new ErrorInfo();
            error.setErrorCode(ex.getClass().getName());
            error.setErrorMessage(ex.getMessage());
            errorKeyPair.setErrorInfo(error);
            return errorKeyPair;
        }

    }

    @ApiOperation(value = "Generate the shared key for the given remote public key (other party in X509encoded Spec) and our private key (our private key encoded in PKCS#8 format) ")
    @PostMapping(value = "/getSharedKey", consumes = "application/json", produces = "application/json")
    @ApiResponses({ @ApiResponse(code = 201, message = " successfully derived the key"),
			@ApiResponse(code = 500, message = " error occured while deriving secret key") })
    public SerializedSecretKey getSharedKey(@RequestBody SecretKeySpec spec) {
        try {
            log.info("Generate Shared Secret");
            log.log(Level.FINE, "Get PrivateKey");
            Key ourPrivateKey = eccService.getPEMDecodedStream(spec.getOurPrivateKey(), true);
            log.log(Level.FINE, "Get PublicKey");
            Key ourPublicKey = eccService.getPEMDecodedStream(spec.getRemotePublicKey(), false);
            log.log(Level.FINE, "Got the key decoded. Lets generate secret key");
            final String secretKey = dheService.getSharedSecret(
                    (PrivateKey) ourPrivateKey,
                    (PublicKey) ourPublicKey);
            return new SerializedSecretKey(secretKey);
        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeyException
                | InvalidKeySpecException ex) {
            log.log(Level.SEVERE, "Error when deriving secret key");
            SerializedSecretKey errorKeyPair = new SerializedSecretKey("");
            ErrorInfo error = new ErrorInfo();
            error.setErrorCode(ex.getClass().getName());
            error.setErrorMessage(ex.getMessage());
            errorKeyPair.setErrorInfo(error);
            return errorKeyPair;
        }
        
    }
    
    @ApiOperation(value = "Generate 256 bit random nonce")
    @GetMapping(value = "/getRandomNonce", produces = "application/json")
    @ApiResponses({ @ApiResponse(code = 201, message = " successfully generated random nonce"),
			@ApiResponse(code = 500, message = " error generating random nonce") })
    public SerializedNonce getRandomNonce(){
        SecureRandom secRan = new SecureRandom(); 
        byte[] ranBytes = new byte[Hash.SHA256.getByteLength()];
        secRan.nextBytes(ranBytes);
        
//        int number = ByteBuffer.wrap(ranBytes).getInt();
//        ByteBuffer newByteBuffer = ByteBuffer.allocate(Hash.SHA256.getByteLength());
//        newByteBuffer.putInt(number);
        
        SerializedNonce serializedNonce = new SerializedNonce(new String(Base64.getEncoder().encode(ranBytes)));
        
        return serializedNonce;
    }
    
   
    @ApiOperation(value = "Generate the session key using sharedSecretKey, rand(u) and rand(p)")
    @PostMapping(value = "/generateSessionKey", produces = "application/json")
    @ApiResponses({ @ApiResponse(code = 201, message = " successfully generated session key"),
			@ApiResponse(code = 500, message = " error occured while deriving session secret key") })
    public SerializedSecretKey generateSessionKeyForEncryption(@RequestBody HKDFInput hkdfInput){
        
        return new SerializedSecretKey(hKDFService.getHKDFSessionKey(hkdfInput));
    
    }


    @ApiOperation(value = "Encrypt Data")
    @PostMapping(value = "/encryptData", consumes = "application/json", produces = "application/json")
    @ApiResponses({ @ApiResponse(code = 201, message = " successfully encrypted data"),
			@ApiResponse(code = 500, message = " error occured while encrypting data") })
    public SerializedEncryptedData encryptData(@RequestBody EncryptionSpec encryptionSpec){
        try{
            
            SerializedEncryptedData serializedEncryptedData = new SerializedEncryptedData(aESService.encryptData(encryptionSpec));
            
            return serializedEncryptedData;
        }
        catch(Exception ex){
            log.log(Level.SEVERE, "Exception in decrypting data "+ex);
            SerializedEncryptedData errorData = new SerializedEncryptedData("");
            ErrorInfo error = new ErrorInfo();
            error.setErrorCode(ex.getClass().getName());
            error.setErrorMessage(ex.getMessage());
            errorData.setErrorInfo(error);
            return errorData;
        }    
    }

    @ApiOperation(value = "Decrypt Data")
    @PostMapping(value = "/decryptData", consumes = "application/json", produces = "application/json")
    @ApiResponses({ @ApiResponse(code = 201, message = " successfully derived the key"),
			@ApiResponse(code = 500, message = " error occured while decrypting data") })
    public SerializedDecryptedData decryptData(@RequestBody DecryptionSpec decryptionSpec){
        try{
            
            SerializedDecryptedData serializedDecryptedData = new SerializedDecryptedData(aESService.decryptData(decryptionSpec));
            
            return serializedDecryptedData;
        }
        catch(Exception ex){
            log.log(Level.SEVERE, "Exception in decryption data "+ex);
            SerializedDecryptedData errorData = new SerializedDecryptedData("");
            ErrorInfo error = new ErrorInfo();
            error.setErrorCode(ex.getClass().getName());
            error.setErrorMessage(ex.getMessage());
            errorData.setErrorInfo(error);
            return errorData;
        }
    }

    
}
