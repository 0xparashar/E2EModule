package com.parashar.e2e.controller;

import com.parashar.e2e.dto.DecryptionParameter;
import com.parashar.e2e.dto.ErrorInfo;
import com.parashar.e2e.dto.SerializedDecryptedData;
import com.parashar.e2e.dto.SessionSpec;
import com.parashar.e2e.service.FIUService;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import java.util.logging.Level;
import lombok.extern.java.Log;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author parashar
 */
@Log
@RestController
@RequestMapping("/fiu/v1")
public class FIUController {
    
    @Autowired
    private FIUService fiuService;
    

    @ApiOperation(value = "Get Session Spec for Intiating request to be used by FIU")
    @GetMapping(value = "/generateSessionSpec", produces = "application/json")
    @ApiResponses({ @ApiResponse(code = 201, message = " successfully derived the params"),
			@ApiResponse(code = 500, message = " error occured while generating keys and params") })
    public SessionSpec generateSessionSpec(){
        try{
            return fiuService.generateSessionSpec();
        }
        catch(Exception ex){
            log.log(Level.SEVERE, "Exception in generating session spec "+ex);

            ErrorInfo error = new ErrorInfo();
            error.setErrorCode(ex.getClass().getName());
            error.setErrorMessage(ex.getMessage());
            SessionSpec errorSpec = new SessionSpec("", "", "", error);
            return errorSpec;
        }
    }

    
    
    
    @ApiOperation(value = "Decrypt Data to be used by FIU")
    @PostMapping(value = "/decrypt", consumes = "application/json", produces = "application/json")
    @ApiResponses({ @ApiResponse(code = 201, message = " successfully derived the key"),
			@ApiResponse(code = 500, message = " error occured while decrypting data") })
    public SerializedDecryptedData decryptData(@RequestBody DecryptionParameter decryptionParameter){
        try{
            
            return fiuService.decrypt(decryptionParameter);
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
