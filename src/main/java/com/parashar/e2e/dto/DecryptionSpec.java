/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.parashar.e2e.dto;

import javax.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.ToString;

/**
 *
 * @author parashar
 */
@ToString(includeFieldNames=true)
@Data
@AllArgsConstructor
public class DecryptionSpec {
    @NotNull
    private String encryptedData;
    @NotNull
    private String sessionKey;
    
    public DecryptionSpec(){
    }

    /**
     * @param encryptedData the encryptedData to set
     */
    public void setEncryptedData(String encryptedData) {
        this.encryptedData = encryptedData;
    }

    /**
     * @param sessionKey the sessionKey to set
     */
    public void setSessionKey(String sessionKey) {
        this.sessionKey = sessionKey;
    }
    
}
