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
public class HKDFInput {
    @NotNull
    private String sharedSecret;
    
    @NotNull
    private Integer remoteRandom;
    
    @NotNull
    private Integer ourRandom;

    /**
     * @return the sharedSecret
     */
    public String getSharedSecret() {
        return sharedSecret;
    }

    /**
     * @param sharedSecret the sharedSecret to set
     */
    public void setSharedSecret(String sharedSecret) {
        this.sharedSecret = sharedSecret;
    }

    /**
     * @return the remoteRandom
     */
    public Integer getRemoteRandom() {
        return remoteRandom;
    }

    /**
     * @param remoteRandom the remoteRandom to set
     */
    public void setRemoteRandom(Integer remoteRandom) {
        this.remoteRandom = remoteRandom;
    }

    /**
     * @return the ourRandom
     */
    public Integer getOurRandom() {
        return ourRandom;
    }

    /**
     * @param ourRandom the ourRandom to set
     */
    public void setOurRandom(Integer ourRandom) {
        this.ourRandom = ourRandom;
    }
    
    
    
}
