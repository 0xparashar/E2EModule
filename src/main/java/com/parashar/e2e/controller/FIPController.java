/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.parashar.e2e.controller;

import com.parashar.e2e.dto.EncryptedSpec;
import com.parashar.e2e.dto.EncryptionParameter;
import com.parashar.e2e.dto.ErrorInfo;
import com.parashar.e2e.service.FIPService;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import java.util.logging.Level;
import lombok.extern.java.Log;
import org.springframework.beans.factory.annotation.Autowired;
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
@RequestMapping("/fip/v1")
public class FIPController {
    
    @Autowired
    private FIPService fipService;
    
    @ApiOperation(value = "Encrypting Data to be used by FIP")
    @PostMapping(value = "/encrypt", consumes = "application/json", produces = "application/json")
    @ApiResponses({ @ApiResponse(code = 201, message = " successfully encrypted data"),
			@ApiResponse(code = 500, message = " error occured while encrypting data") })
    public EncryptedSpec encryptData(@RequestBody EncryptionParameter encryptionParameter){
        try{
            
            return fipService.encrypt(encryptionParameter);
        }
        catch(Exception ex){
            log.log(Level.SEVERE, "Exception in encrypting data "+ex);

            ErrorInfo error = new ErrorInfo();
            error.setErrorCode(ex.getClass().getName());
            error.setErrorMessage(ex.getMessage());
            EncryptedSpec errorData = new EncryptedSpec("","","","",error);
            return errorData;
        }    
    }
    
    
}
